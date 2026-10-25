#include <gatekeeper/resolve.h>
#include <gatekeeper/client/state.h>
#include <gatekeeper/config.h>
#include <gatekeeper/host.h>
#include <gatekeeper/sql.h>
#include <gatekeeper/event.h>
#include <authum/client.h>
#include <authum/host/tasks.h>
#include <authum/host/events.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

authum_host_t g_gatekeeper_host;
authum_logger_t g_gatekeeper_logger;
static int failures, kicks, last_kick, resolved, finished, current_user = 101;
static atomic_int released;
#define CHECK(x)                                                                                   \
    do                                                                                             \
    {                                                                                              \
        if (!(x))                                                                                  \
        {                                                                                          \
            ++failures;                                                                            \
            fprintf(stderr, "line %d: %s\n", __LINE__, #x);                                        \
        }                                                                                          \
    } while (0)
void
pause_ms(void)
{
    struct timespec t = {0, 1000000};
    nanosleep(&t, NULL);
}
authum_i32_t
userid(authum_i32_t index)
{
    return index == 1 ? current_user : 0;
}
void
kick(const authum_char_t *command)
{
    int id = 0;
    if (sscanf(command, "kick #%d", &id) == 1)
    {
        ++kicks;
        last_kick = id;
    }
}
void
block(void *user)
{
    (void)user;
    while (!atomic_load(&released))
    {
        pause_ms();
    }
}
void
no_work(void *user)
{
    (void)user;
}
void
mark(void *user)
{
    (void)user;
    finished = 1;
}
void
drain(void)
{
    unsigned i;
    finished = 0;
    CHECK(authum_tasks_submit(authum_host_tasks(&g_gatekeeper_host), no_work, mark, NULL, NULL));
    for (i = 0; i < 5000 && !finished; ++i)
    {
        authum_tasks_host_pump();
        pause_ms();
    }
    CHECK(finished);
}
authum_event_result_t
seen(const authum_char_t *name, void *payload, void *user)
{
    (void)name;
    (void)payload;
    (void)user;
    ++resolved;
    return authum_event_result_continue;
}
void
event(const char *name, const char *ip)
{
    authum_event_client_t ev;
    memset(&ev, 0, sizeof ev);
    ev.size = sizeof ev;
    ev.index = 1;
    ev.userid = current_user;
    ev.allow = authum_bool_true;
    snprintf(ev.address, sizeof ev.address, "%s:27005", ip);
    snprintf(ev.auth_id, sizeof ev.auth_id, "STEAM_0:1:424244");
    authum_host_publish(&g_gatekeeper_host, name, &ev);
    CHECK(ev.allow); /* no network work or synchronous reject in ClientConnect */
}
void
connect_ip(const char *ip)
{
    event(AUTHUM_EVENT_CLIENT_CONNECT, ip);
    event(AUTHUM_EVENT_CLIENT_PUT_IN_SERVER, ip);
}
int
main(void)
{
    authum_engine_t engine;
    authum_tasks_t tasks;
    authum_events_t events;
    authum_sql_t db;
    char path[] = "/tmp/gatekeeper-async-XXXXXX";
    int owner, fd = mkstemp(path), before;
    CHECK(fd >= 0);
    if (fd < 0)
    {
        return 1;
    }
    close(fd);
    memset(&g_gatekeeper_host, 0, sizeof g_gatekeeper_host);
    g_gatekeeper_host.size = sizeof g_gatekeeper_host;
    memset(&engine, 0, sizeof engine);
    engine.size = sizeof engine;
    engine.client_userid = userid;
    engine.server_command = kick;
    g_gatekeeper_host.engine = &engine;
    tasks.ops = authum_tasks_host_ops();
    tasks.owner = &owner;
    g_gatekeeper_host.tasks = &tasks;
    events.ops = authum_events_host_ops();
    events.owner = &owner;
    g_gatekeeper_host.events = &events;
    authum_logger_init(&g_gatekeeper_logger, &g_gatekeeper_host);
    g_gatekeeper_config.sql_driver = gatekeeper_sql_driver_sqlite;
    authum_cstr_copy(g_gatekeeper_config.sql_path, sizeof g_gatekeeper_config.sql_path, path);
    g_gatekeeper_config.iphub_enabled = authum_bool_false;
    g_gatekeeper_config.steam_guard_enforce = authum_bool_true;
    authum_cstr_copy(g_gatekeeper_config.filter_countries,
                     sizeof g_gatekeeper_config.filter_countries, "RU");
    authum_sql_init(&db);
    CHECK(authum_sql_open_sqlite(&db, path));
    gatekeeper_sql_bind(&db);
    CHECK(gatekeeper_sql_ensure_schema());
    gatekeeper_sql_bind(NULL);
    CHECK(authum_sql_exec(
        &db, "INSERT INTO user(asn,ip,code,name,isp,block) VALUES "
             "(1,'192.0.2.10','RU','lab','lab',0),(2,'192.0.2.11','US','lab','lab',0)"));
    CHECK(authum_sql_ping(&db));
    authum_sql_close(&db);
    CHECK(gatekeeper_client_state_start());
    CHECK(gatekeeper_resolve_start());
    CHECK(authum_host_subscribe(&g_gatekeeper_host, GATEKEEPER_EVENT_CLIENT_RESOLVED, seen, NULL));
    drain();
    connect_ip("192.0.2.10");
    drain();
    CHECK(resolved == 1);
    CHECK(kicks == 0);
    connect_ip("192.0.2.11");
    drain();
    CHECK(resolved == 2);
    CHECK(kicks == 1);
    CHECK(last_kick == 101);

    /* A new connection in the same slot, even with an identical userid,
     * must not receive the old connection's decision. */
    before = resolved;
    atomic_store(&released, 0);
    CHECK(authum_tasks_submit(&tasks, block, NULL, NULL, NULL));
    connect_ip("192.0.2.11");
    event(AUTHUM_EVENT_CLIENT_DISCONNECT, "192.0.2.11");
    event(AUTHUM_EVENT_CLIENT_CONNECT, "192.0.2.10");
    atomic_store(&released, 1);
    drain();
    CHECK(resolved == before);
    CHECK(kicks == 1);

    /* Engine userid is a second independent guard. */
    atomic_store(&released, 0);
    CHECK(authum_tasks_submit(&tasks, block, NULL, NULL, NULL));
    connect_ip("192.0.2.11");
    current_user = 202;
    atomic_store(&released, 1);
    drain();
    CHECK(kicks == 1);

    atomic_store(&released, 0);
    CHECK(authum_tasks_submit(&tasks, block, NULL, NULL, NULL));
    connect_ip("192.0.2.11");
    authum_host_publish(&g_gatekeeper_host, AUTHUM_EVENT_SERVER_DEACTIVATE, NULL);
    atomic_store(&released, 1);
    drain();
    CHECK(kicks == 1);

    /* Pending and active callbacks are suppressed before module state dies. */
    atomic_store(&released, 0);
    CHECK(authum_tasks_submit(&tasks, block, NULL, NULL, NULL));
    connect_ip("192.0.2.11");
    atomic_store(&released, 1);
    authum_tasks_host_drop_owner(&owner);
    gatekeeper_resolve_stop();
    gatekeeper_client_state_stop();
    authum_events_host_drop_owner(&owner);
    authum_tasks_host_pump();
    CHECK(kicks == 1);
    unlink(path);
    printf("gatekeeper async: %d failures\n", failures);
    return failures ? 1 : 0;
}