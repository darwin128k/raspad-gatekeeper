#ifndef GATEKEEPER_IPHUB_DATA_H
#define GATEKEEPER_IPHUB_DATA_H

#include <authum/char.h>
#include <authum/size.h>

enum {
	gatekeeper_ip_size = 46,
	gatekeeper_country_code_size = 8,
	gatekeeper_country_name_size = 64,
	gatekeeper_isp_size = 96
};

struct gatekeeper_iphub_data
{
	authum_i32_t id; /* SQL row id, -1 if none */
	authum_i32_t asn;
	authum_char_t ip[gatekeeper_ip_size];
	authum_char_t code[gatekeeper_country_code_size];
	authum_char_t name[gatekeeper_country_name_size];
	authum_char_t isp[gatekeeper_isp_size];
	authum_i32_t block;
};
typedef struct gatekeeper_iphub_data gatekeeper_iphub_data_t;

void gatekeeper_iphub_data_clear(gatekeeper_iphub_data_t *self);

#endif /* GATEKEEPER_IPHUB_DATA_H */
