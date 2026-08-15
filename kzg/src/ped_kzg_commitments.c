#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include "relic.h"
#include "ped_kzg_commitments.h"

int threshold;
int scalar_size;
int point_size;
int prime_size;
bn_t sub_prime_field;
bn_t prime_field;
ep2_t g2_base;
ep_t *g_pk;
ep_t *h_pk;
bn_t zero_bn;
ep2_t gAlpha;
fp12_t gPairing;
fp12_t hPairing;
ep_t *commitment_bases;
ep_t *witness_bases;

int initialize_relic() {
	if (core_init() != RLC_OK) {
		printf("Could not initialize\n");
		core_clean();
		return -1;
	}

	if (pc_param_set_any() != RLC_OK) {
		printf("Could not set pairing parameters\n");
		core_clean();
		return -1;
	}

	//printf("\n=== Curve parameters start ===\n");
	pc_param_print();

	//printf("\nSecurity level: %d bits\n", pc_param_level());
	//printf("\n=== Curve parameters end ===\n");

	bn_null(sub_prime_field);
	bn_null(prime_field);
	bn_new(sub_prime_field);
	bn_new(prime_field);

	bn_read_raw(prime_field, fp_prime_get(), RLC_FP_DIGS);
	prime_size = bn_size_bin(prime_field);

	pc_get_ord(sub_prime_field);
	// printf("\nGroup sub_prime_field:\n");
	// bn_print(sub_prime_field);

	return 0;
}

int initialize_kzg(int t, bn_t alpha_input) {
	threshold = t;

	ep2_null(g2_base);
	ep2_new(g2_base);
	ep2_curve_get_gen(g2_base);

	bn_null(zero_bn);
	bn_new(zero_bn);
	bn_set_dig(zero_bn, 0);

	const uint8_t h_dst[] = "cobra-ped-kzg-h-generator-v1";

	ep_t g_base;
	ep_t h_base;

	ep_null(g_base);
	ep_null(h_base);

	ep_new(g_base);
	ep_new(h_base);

	ep_curve_get_gen(g_base);

	ep_map(h_base, h_dst, sizeof(h_dst) - 1);
    ep_norm(h_base, h_base);

	bn_t alpha, alpha_power;
	bn_null(alpha);
	bn_null(alpha_power);
	bn_new(alpha);
	bn_new(alpha_power);

	bn_copy(alpha, alpha_input);

	bn_set_dig(alpha_power, 1);

	ep2_null(gAlpha);
	ep2_new(gAlpha);
	ep2_mul_gen(gAlpha, alpha);

	fp12_null(gPairing);
	fp12_null(hPairing);
	fp12_new(gPairing);
	fp12_new(hPairing);

	pp_map_oatep_k12(gPairing, g_base, g2_base);
	pp_map_oatep_k12(hPairing, h_base, g2_base);

	//pre-computing public data of commitment scheme
	g_pk = (ep_t *)malloc(sizeof(ep_t) * (t + 1));
	h_pk = (ep_t *)malloc(sizeof(ep_t) * (t + 1));

	for (int i = 0; i <= t; i++) {
		ep_null(g_pk[i]);
		ep_null(h_pk[i]);

		ep_new(g_pk[i]);
		ep_new(h_pk[i]);

		ep_mul(g_pk[i], g_base, alpha_power);
		ep_mul(h_pk[i], h_base, alpha_power);

		ep_norm(g_pk[i], g_pk[i]);
		ep_norm(h_pk[i], h_pk[i]);

		bn_mul(alpha_power, alpha_power, alpha);
		bn_mod(alpha_power, alpha_power, sub_prime_field);
	}

	commitment_bases = malloc(sizeof(ep_t) * 2 * (t + 1));
	for (int i = 0; i <= t; i++) {
		ep_null(commitment_bases[i]);
		ep_new(commitment_bases[i]);
		ep_copy(commitment_bases[i], g_pk[t - i]);

		ep_null(commitment_bases[t + 1 + i]);
		ep_new(commitment_bases[t + 1 + i]);
		ep_copy(commitment_bases[t + 1 + i], h_pk[t - i]);
	}

	witness_bases = malloc(sizeof(ep_t) * 2 * t);
	for (int i = 0; i < t; i++) {
		ep_null(witness_bases[i]);
		ep_new(witness_bases[i]);
		ep_copy(witness_bases[i], g_pk[t - 1 - i]);

		ep_null(witness_bases[t + i]);
		ep_new(witness_bases[t + i]);
		ep_copy(witness_bases[t + i], h_pk[t - 1 - i]);
	}

	bn_free(alpha);
	bn_free(alpha_power);

	ep_free(g_base);
	ep_free(h_base);

	return 0;
}

void clean() {
	bn_free(zero_bn);
	bn_free(prime_field);
	bn_free(sub_prime_field);
	ep2_free(g2_base);
	ep2_free(gAlpha);
	fp12_free(gPairing);
	fp12_free(hPairing);

	for (int i = 0; i <= threshold; i++) {
		ep_free(g_pk[i]);
		ep_free(h_pk[i]);
		ep_free(commitment_bases[i]);
		ep_free(commitment_bases[threshold + 1 + i]);
	}
	free(commitment_bases);

	for(int i = 0; i < 2 * threshold; i++) {
		ep_free(witness_bases[i]);
	}
	free(witness_bases);

	free(g_pk);
	free(h_pk);

	core_clean();
}

int jna_initialize(int threshold, uint8_t *alpha, int alpha_length) {
	int status = initialize_relic();
	if (status == -1) {
		return -1;
	}


	bn_t new_alpha;
	bn_null(new_alpha);
	bn_new(new_alpha);
	bn_read_bin(new_alpha, alpha, alpha_length);
	bn_mod(new_alpha, new_alpha, sub_prime_field);

	status = initialize_kzg(threshold, new_alpha);

	scalar_size = (bn_bits(sub_prime_field) + 7) / 8;
	point_size = ep_size_bin(g_pk[0], 1);

	return status;
}

int jna_scalar_size() {
    return scalar_size;
}

int jna_prime_size() {
	return prime_size;
}

int jna_g1_size() {
    return point_size;
}

int jna_get_sub_prime_field(uint8_t *sub_prime_field_out) {
	if (sub_prime_field_out == NULL) {
		return -1;
	}

	bn_write_bin(sub_prime_field_out, scalar_size, sub_prime_field);

	return 0;
}

int jna_get_prime_field(uint8_t *prime_out) {
	if (prime_out == NULL) {
		return -1;
	}

	bn_write_bin(prime_out, prime_size, prime_field);
	return 0;
}

void jna_clean() {
	clean();
}

static int read_g1_point(ep_t out, const uint8_t *bytes) {
	int all_zero = 1;
	for (int i = 0; i < point_size; i++) {
		if (bytes[i] != 0) {
			all_zero = 0;
			break;
		}
	}

	if (all_zero) {
		ep_set_infty(out);
		return 0;
	}

	ep_read_bin(out, bytes, point_size);
	return 0;
}

int bytes_array_to_bn_t(uint8_t *flatten_bytes_array, int array_len, bn_t *result) {
	if (flatten_bytes_array == NULL || result == NULL) {
		return -1;
	}

	for (int i = 0; i < array_len; i++) {
		bn_null(result[i]);
		bn_new(result[i]);
		bn_read_bin(result[i], &flatten_bytes_array[i * scalar_size], scalar_size);
	}

	return 0;
}

int free_bn_t_array(bn_t *array, int array_len) {
	if (array == NULL) {
		return -1;
	}

	for (int i = 0; i < array_len; i++) {
		bn_free(array[i]);
	}

	free(array);
	return 0;
}

static int compute_quotient_coefficients_ped(bn_t *secret_coefficients, bn_t *blinding_coefficients, bn_t x,
    bn_t *witness_scalars) {
    if (secret_coefficients == NULL || blinding_coefficients == NULL || x == NULL || witness_scalars == NULL) {
        return -1;
    }

    bn_copy(witness_scalars[0], secret_coefficients[0]);
    bn_mod(witness_scalars[0], witness_scalars[0], sub_prime_field);

    bn_copy(witness_scalars[threshold], blinding_coefficients[0]);
    bn_mod(witness_scalars[threshold], witness_scalars[threshold], sub_prime_field);

    for (int i = 1; i < threshold; i++) {
        bn_mul(witness_scalars[i], x, witness_scalars[i - 1]);
        bn_mod(witness_scalars[i], witness_scalars[i], sub_prime_field);
        bn_add(witness_scalars[i], witness_scalars[i], secret_coefficients[i]);
        bn_mod(witness_scalars[i], witness_scalars[i], sub_prime_field);

        bn_mul(witness_scalars[threshold + i], x, witness_scalars[threshold + i - 1]);
        bn_mod(witness_scalars[threshold + i], witness_scalars[threshold + i], sub_prime_field);
        bn_add(witness_scalars[threshold + i], witness_scalars[threshold + i], blinding_coefficients[i]);
        bn_mod(witness_scalars[threshold + i], witness_scalars[threshold + i], sub_prime_field);
    }

    return 0;
}

int compute_witnesses_ped(bn_t *secret_coefficients, bn_t *blinding_coefficients, bn_t *shareholders, int n_shareholders,
    ep_t *witnesses) {
    if (secret_coefficients == NULL ||
        blinding_coefficients == NULL ||
        shareholders == NULL ||
        witnesses == NULL) {
        return -1;
    }

    bn_t *witness_scalars = malloc(sizeof(bn_t) * 2 * threshold);

    for (int i = 0; i < 2 * threshold; i++) {
        bn_null(witness_scalars[i]);
        bn_new(witness_scalars[i]);
    }

    for (int i = 0; i < n_shareholders; i++) {
        int status = compute_quotient_coefficients_ped(secret_coefficients, blinding_coefficients, shareholders[i],
            witness_scalars);

        if (status != 0) {
            for (int i = 0; i < 2 * threshold; i++) {
				bn_free(witness_scalars[i]);
			}

			free(witness_scalars);
            return -1;
        }

        ep_mul_sim_lot(witnesses[i], witness_bases, witness_scalars, 2 * threshold);
    }

    for (int i = 0; i < 2 * threshold; i++) {
        bn_free(witness_scalars[i]);
    }

    free(witness_scalars);

    return 0;
}

int commit_and_create_witnesses_ped(bn_t *secret_coefficients, bn_t *blinding_coefficients,
	bn_t *shareholders, int n_shareholders, bn_t *additional_shareholders, int n_additional_shareholders,
	ep_t commitment, ep_t *witnesses, ep_t *additional_witnesses) {

	if (secret_coefficients == NULL || blinding_coefficients == NULL || shareholders == NULL || commitment == NULL || witnesses == NULL) {
		return -1;
	}

	bn_t *commitment_scalars = malloc(sizeof(bn_t) * 2 * (threshold + 1));

	//compute commitment
	for (int i = 0; i <= threshold; i++) {
		bn_null(commitment_scalars[i]);
		bn_null(commitment_scalars[threshold + 1 + i]);
		bn_new(commitment_scalars[i]);
		bn_new(commitment_scalars[threshold + 1 + i]);
		bn_copy(commitment_scalars[i], secret_coefficients[i]);
		bn_copy(commitment_scalars[threshold + 1 + i], blinding_coefficients[i]);
	}

	ep_mul_sim_lot(commitment, commitment_bases, commitment_scalars, 2 * (threshold + 1));

	//compute witnesses
	int status = compute_witnesses_ped(secret_coefficients, blinding_coefficients, shareholders, n_shareholders, witnesses);
	if (status != 0) {
		for (int i = 0; i <= threshold; i++) {
			bn_free(commitment_scalars[i]);
			bn_free(commitment_scalars[threshold + 1 + i]);
		}

		free(commitment_scalars);
		return -1;
	}

	if (n_additional_shareholders > 0) {
		status = compute_witnesses_ped(secret_coefficients, blinding_coefficients, additional_shareholders,
				n_additional_shareholders, additional_witnesses);
		if (status != 0) {
			for (int i = 0; i <= threshold; i++) {
				bn_free(commitment_scalars[i]);
				bn_free(commitment_scalars[threshold + 1 + i]);
			}

			free(commitment_scalars);
			return -1;
		}
	}

	for (int i = 0; i <= threshold; i++) {
		bn_free(commitment_scalars[i]);
		bn_free(commitment_scalars[threshold + 1 + i]);
	}

	free(commitment_scalars);

	return 0;
}

int jna_commit_and_create_witnesses_ped(uint8_t *secret_coefficients, uint8_t *blinding_coefficients,
                                    	uint8_t *shareholders, int n_shareholders,
                                    	uint8_t *additional_shareholders, int n_additional_shareholders,
                                    	uint8_t *commitment, uint8_t *witnesses, uint8_t *additional_witnesses) {
	if (secret_coefficients == NULL || blinding_coefficients == NULL || shareholders == NULL
		|| additional_shareholders == NULL || commitment == NULL || witnesses == NULL || additional_witnesses == NULL) {
		return -1;
	}

	bn_t *secret_coeffs_bn = (bn_t *)malloc(sizeof(bn_t) * (threshold + 1));
	bn_t *blinding_coeffs_bn = (bn_t *)malloc(sizeof(bn_t) * (threshold + 1));
	bn_t *shareholders_bn = (bn_t *)malloc(sizeof(bn_t) * n_shareholders);
	bn_t *additional_shareholders_bn = (bn_t *)malloc(sizeof(bn_t) * n_additional_shareholders);

	bytes_array_to_bn_t(secret_coefficients, threshold + 1, secret_coeffs_bn);
	bytes_array_to_bn_t(blinding_coefficients, threshold + 1, blinding_coeffs_bn);
	bytes_array_to_bn_t(shareholders, n_shareholders, shareholders_bn);
	bytes_array_to_bn_t(additional_shareholders, n_additional_shareholders, additional_shareholders_bn);

	ep_t commitment_ep;
	ep_null(commitment_ep);
	ep_new(commitment_ep);
	ep_t *witnesses_ep = (ep_t *)malloc(sizeof(ep_t) * n_shareholders);
	ep_t *additional_witnesses_ep = (ep_t *)malloc(sizeof(ep_t) * n_additional_shareholders);
	for (int i = 0; i < n_shareholders; i++) {
		ep_null(witnesses_ep[i]);
		ep_new(witnesses_ep[i]);
	}
	for (int i = 0; i < n_additional_shareholders; i++) {
		ep_null(additional_witnesses_ep[i]);
		ep_new(additional_witnesses_ep[i]);
	}

	int status = commit_and_create_witnesses_ped(secret_coeffs_bn, blinding_coeffs_bn, shareholders_bn, n_shareholders,
		additional_shareholders_bn, n_additional_shareholders, commitment_ep, witnesses_ep, additional_witnesses_ep);
	if (status != 0) {
		return -1;
	}

	ep_write_bin(commitment, point_size, commitment_ep, 1);
	for (int i = 0; i < n_shareholders; i++) {
		ep_write_bin(&witnesses[i * point_size], point_size, witnesses_ep[i], 1);
	}
	for (int i = 0; i < n_additional_shareholders; i++) {
		ep_write_bin(&additional_witnesses[i * point_size], point_size, additional_witnesses_ep[i], 1);
	}

	ep_free(commitment_ep);
	for (int i = 0; i < n_shareholders; i++) {
		ep_free(witnesses_ep[i]);
	}
	for (int i = 0; i < n_additional_shareholders; i++) {
		ep_free(additional_witnesses_ep[i]);
	}
	free(witnesses_ep);
	free(additional_witnesses_ep);

	free_bn_t_array(secret_coeffs_bn, threshold + 1);
	free_bn_t_array(blinding_coeffs_bn, threshold + 1);
	free_bn_t_array(shareholders_bn, n_shareholders);
	free_bn_t_array(additional_shareholders_bn, n_additional_shareholders);
	return 0;
}

int verify_share_ped(bn_t shareholder, bn_t secret_share, bn_t blinding_share, ep_t commitment, ep_t witness) {
    if (shareholder == NULL || secret_share == NULL || blinding_share == NULL || commitment == NULL || witness == NULL) {
        return -1;
    }

    ep_t pairing_g1[2];

	ep2_t shareholder_g2;
	ep2_t alpha_minus_shareholder_g2;
	ep2_t pairing_g2[2];

	fp12_t lhs;
	fp12_t rhs_g;
	fp12_t rhs_h;
	fp12_t rhs;

	ep2_null(shareholder_g2);
	ep2_null(alpha_minus_shareholder_g2);
	fp12_null(lhs);
	fp12_null(rhs_g);
	fp12_null(rhs_h);
	fp12_null(rhs);

	ep2_new(shareholder_g2);
	ep2_new(alpha_minus_shareholder_g2);
	fp12_new(lhs);
	fp12_new(rhs_g);
	fp12_new(rhs_h);
	fp12_new(rhs);

	for (int i = 0; i < 2; i++) {
	  ep_null(pairing_g1[i]);
	  ep_new(pairing_g1[i]);

	  ep2_null(pairing_g2[i]);
	  ep2_new(pairing_g2[i]);
	}

	/*
	* lhs = e(C, g) * e(-witness, gAlpha - shareholder*g)
	*/
	ep_copy(pairing_g1[0], commitment);
	ep2_copy(pairing_g2[0], g2_base);

	ep_neg(pairing_g1[1], witness);

	ep2_mul_gen(shareholder_g2, shareholder);
	ep2_sub(alpha_minus_shareholder_g2, gAlpha, shareholder_g2);
	ep2_copy(pairing_g2[1], alpha_minus_shareholder_g2);

	pp_map_sim_oatep_k12(lhs, pairing_g1, pairing_g2, 2);

	/*
	* rhs = e(g, g)^secret_share * e(h, g)^blinding_share
	*/
	fp12_exp(rhs_g, gPairing, secret_share);
	fp12_exp(rhs_h, hPairing, blinding_share);
	fp12_mul(rhs, rhs_g, rhs_h);

	int valid = fp12_cmp(lhs, rhs) == RLC_EQ;

	for (int i = 0; i < 2; i++) {
	  ep_free(pairing_g1[i]);
	  ep2_free(pairing_g2[i]);
	}

	fp12_free(rhs);
	fp12_free(rhs_h);
	fp12_free(rhs_g);
	fp12_free(lhs);
	ep2_free(alpha_minus_shareholder_g2);
	ep2_free(shareholder_g2);

	return valid;
}

int jna_verify_share_ped(uint8_t *shareholder, uint8_t *secret_share, uint8_t *blinding_share, uint8_t *commitment, uint8_t *witness) {
	if (shareholder == NULL || secret_share == NULL || blinding_share == NULL || commitment == NULL || witness == NULL) {
		return -1;
	}

	bn_t shareholder_bn, secret_share_bn, blinding_share_bn;
	bn_null(shareholder_bn);
	bn_null(secret_share_bn);
	bn_null(blinding_share_bn);
	bn_new(shareholder_bn);
	bn_new(secret_share_bn);
	bn_new(blinding_share_bn);
	bn_read_bin(shareholder_bn, shareholder, scalar_size);
	bn_read_bin(secret_share_bn, secret_share, scalar_size);
	bn_read_bin(blinding_share_bn, blinding_share, scalar_size);

	ep_t commitment_ep, witness_ep;
	ep_null(commitment_ep);
	ep_null(witness_ep);
	ep_new(commitment_ep);
	ep_new(witness_ep);
	read_g1_point(commitment_ep, commitment);
	read_g1_point(witness_ep, witness);

	int valid = verify_share_ped(shareholder_bn, secret_share_bn, blinding_share_bn, commitment_ep, witness_ep);

	bn_free(shareholder_bn);
	bn_free(secret_share_bn);
	bn_free(blinding_share_bn);
	ep_free(commitment_ep);
	ep_free(witness_ep);
	return valid;
}

int jna_add_points(uint8_t *points, int length, uint8_t *result) {
	if (points == NULL || result == NULL || length < 0) {
		return -1;
	}

	ep_t point_ep, result_ep;
	ep_null(point_ep);
	ep_null(result_ep);
	ep_new(point_ep);
	ep_new(result_ep);

	ep_set_infty(result_ep);

	for (int i = 0; i < length; i++) {
		read_g1_point(point_ep, &points[i * point_size]);
		ep_add(result_ep, result_ep, point_ep);
	}

	ep_write_bin(result, point_size, result_ep, 1);

	ep_free(point_ep);
	ep_free(result_ep);

	return 0;
}

//Returns point_a - point_b
int jna_subtract_points(uint8_t *point_a, uint8_t *point_b, uint8_t *result) {
	if (point_a == NULL || point_b == NULL || result == NULL) {
		return -1;
	}

	ep_t point_a_ep, point_b_ep, result_ep;
	ep_null(point_a_ep);
	ep_null(point_b_ep);
	ep_null(result_ep);
	ep_new(point_a_ep);
	ep_new(point_b_ep);
	ep_new(result_ep);

	read_g1_point(point_a_ep, point_a);
	read_g1_point(point_b_ep, point_b);
	ep_sub(result_ep, point_a_ep, point_b_ep);

	ep_write_bin(result, point_size, result_ep, 1);

	ep_free(point_a_ep);
	ep_free(point_b_ep);
	ep_free(result_ep);

	return 0;
}

int jna_add_constant_to_point(uint8_t *point, uint8_t *constant, uint8_t *result) {
	if (point == NULL || constant == NULL || result == NULL) {
		return -1;
	}

	ep_t point_ep, c_g, result_ep;
	ep_null(point_ep);
	ep_null(c_g);
	ep_null(result_ep);
	ep_new(point_ep);
	ep_new(c_g);
	ep_new(result_ep);

	bn_t constant_bn;
	bn_null(constant_bn);
	bn_new(constant_bn);

	read_g1_point(point_ep, point);
	bn_read_bin(constant_bn, constant, scalar_size);

	ep_mul(c_g, g_pk[0], constant_bn);

	ep_add(result_ep, point_ep, c_g);

	ep_write_bin(result, point_size, result_ep, 1);

	ep_free(point_ep);
	ep_free(c_g);
	ep_free(result_ep);
	bn_free(constant_bn);

	return 0;
}

int jna_multiply_point_by_constant(uint8_t *point, uint8_t *constant, uint8_t *result) {
	if (point == NULL || constant == NULL || result == NULL) {
		return -1;
	}

	ep_t point_ep, result_ep;
	ep_null(point_ep);
	ep_null(result_ep);
	ep_new(point_ep);
	ep_new(result_ep);

	bn_t constant_bn;
	bn_null(constant_bn);
	bn_new(constant_bn);

	read_g1_point(point_ep, point);
	bn_read_bin(constant_bn, constant, scalar_size);

	ep_mul(result_ep, point_ep, constant_bn);

	ep_write_bin(result, point_size, result_ep, 1);

	ep_free(point_ep);
	ep_free(result_ep);
	bn_free(constant_bn);

	return 0;
}

int jna_multiply_commitment_by_constant(uint8_t *commitment, int n_witnesses, uint8_t *witnesses, uint8_t *constant,
										uint8_t *commitment_result, uint8_t *witnesses_result) {
	if (commitment == NULL || constant == NULL || commitment_result == NULL
		|| (n_witnesses > 0 && (witnesses == NULL || witnesses_result == NULL))) {
		return -1;
	}

	ep_t point_ep, result_ep;
	ep_null(point_ep);
	ep_null(result_ep);
	ep_new(point_ep);
	ep_new(result_ep);

	bn_t constant_bn;
	bn_null(constant_bn);
	bn_new(constant_bn);

	read_g1_point(point_ep, commitment);
	bn_read_bin(constant_bn, constant, scalar_size);

	ep_mul(result_ep, point_ep, constant_bn);

	ep_write_bin(commitment_result, point_size, result_ep, 1);

	for (int i = 0; i < n_witnesses; i++) {
		read_g1_point(point_ep, &witnesses[i * point_size]);
		ep_mul(result_ep, point_ep, constant_bn);
		ep_write_bin(&witnesses_result[i * point_size], point_size, result_ep, 1);
	}

	ep_free(point_ep);
	ep_free(result_ep);
	bn_free(constant_bn);
	return 0;
}

static void free_bn_array_local(bn_t *array, int len) {
	if (array == NULL) {
		return;
	}
	for (int i = 0; i < len; i++) {
		bn_free(array[i]);
	}
	free(array);
}

static void free_ep_array_local(ep_t *array, int len) {
	if (array == NULL) {
		return;
	}
	for (int i = 0; i < len; i++) {
		ep_free(array[i]);
	}
	free(array);
}

static void init_bn_array_local(bn_t *array, int len) {
	for (int i = 0; i < len; i++) {
		bn_null(array[i]);
		bn_new(array[i]);
	}
}

static void init_ep_array_local(ep_t *array, int len) {
	(void)array;
	for (int i = 0; i < len; i++) {
		ep_null(array[i]);
		ep_new(array[i]);
	}
}

static int compute_lagrange_weights(int n, bn_t *xs, bn_t *weights, bn_t tmp) {
	for (int i = 0; i < n; i++) {
		bn_set_dig(weights[i], 1);

		for (int j = 0; j < n; j++) {
			if (i == j) {
				continue;
			}

			bn_sub(tmp, xs[i], xs[j]);
			bn_mod(tmp, tmp, sub_prime_field);
			if (bn_is_zero(tmp)) {
				return -1;
			}

			bn_mul(weights[i], weights[i], tmp);
			bn_mod(weights[i], weights[i], sub_prime_field);
		}
	}

	bn_mod_inv_sim(weights, weights, sub_prime_field, n);
	return 0;
}

static int evaluate_lagrange_g1(ep_t result, bn_t x, int n, bn_t *xs, ep_t *ys, bn_t *weights,
								bn_t *dx, bn_t *inv_dx, bn_t *coeffs, bn_t prod, bn_t tmp) {
	for (int i = 0; i < n; i++) {
		if (bn_cmp(x, xs[i]) == RLC_EQ) {
			ep_copy(result, ys[i]);
			return 0;
		}
	}

	bn_set_dig(prod, 1);
	for (int i = 0; i < n; i++) {
		bn_sub(dx[i], x, xs[i]);
		bn_mod(dx[i], dx[i], sub_prime_field);

		bn_mul(prod, prod, dx[i]);
		bn_mod(prod, prod, sub_prime_field);
	}

	bn_mod_inv_sim(inv_dx, dx, sub_prime_field, n);

	for (int i = 0; i < n; i++) {
		bn_mul(tmp, prod, inv_dx[i]);
		bn_mod(tmp, tmp, sub_prime_field);

		bn_mul(coeffs[i], tmp, weights[i]);
		bn_mod(coeffs[i], coeffs[i], sub_prime_field);
	}

	ep_mul_sim_lot(result, ys, coeffs, n);
	ep_norm(result, result);
	return 0;
}

int jna_recover_witness(uint8_t *recovering_shareholder, int n_witnesses, uint8_t *shareholders,
						uint8_t *witnesses, uint8_t *recovered_witness) {
	if (recovering_shareholder == NULL || n_witnesses < threshold ||
		shareholders == NULL || witnesses == NULL || recovered_witness == NULL) {
		return -1;
	}

	int status = -1;
	int basis_size = threshold;

	bn_t x, tmp, prod;
	ep_t recovered_ep, expected_ep;

	bn_t *xs = malloc(sizeof(bn_t) * n_witnesses);
	bn_t *weights = malloc(sizeof(bn_t) * basis_size);
	bn_t *dx = malloc(sizeof(bn_t) * basis_size);
	bn_t *inv_dx = malloc(sizeof(bn_t) * basis_size);
	bn_t *coeffs = malloc(sizeof(bn_t) * basis_size);
	ep_t *witness_points = malloc(sizeof(ep_t) * n_witnesses);

	if (xs == NULL || weights == NULL || dx == NULL || inv_dx == NULL ||
		coeffs == NULL || witness_points == NULL) {
		free(xs);
		free(weights);
		free(dx);
		free(inv_dx);
		free(coeffs);
		free(witness_points);
		return -1;
	}

	init_bn_array_local(xs, n_witnesses);
	init_bn_array_local(weights, basis_size);
	init_bn_array_local(dx, basis_size);
	init_bn_array_local(inv_dx, basis_size);
	init_bn_array_local(coeffs, basis_size);
	init_ep_array_local(witness_points, n_witnesses);

	bn_null(x);
	bn_null(tmp);
	bn_null(prod);
	ep_null(recovered_ep);
	ep_null(expected_ep);

	bn_new(x);
	bn_new(tmp);
	bn_new(prod);
	ep_new(recovered_ep);
	ep_new(expected_ep);

	bn_read_bin(x, recovering_shareholder, scalar_size);
	bn_mod(x, x, sub_prime_field);

	for (int i = 0; i < n_witnesses; i++) {
		bn_read_bin(xs[i], &shareholders[i * scalar_size], scalar_size);
		bn_mod(xs[i], xs[i], sub_prime_field);
		read_g1_point(witness_points[i], &witnesses[i * point_size]);
	}

	if (compute_lagrange_weights(basis_size, xs, weights, tmp) != 0) {
		goto cleanup;
	}

	if (evaluate_lagrange_g1(recovered_ep, x, basis_size, xs, witness_points, weights,
		dx, inv_dx, coeffs, prod, tmp) != 0) {
		goto cleanup;
	}

	for (int i = basis_size; i < n_witnesses; i++) {
		if (evaluate_lagrange_g1(expected_ep, xs[i], basis_size, xs, witness_points, weights,
			dx, inv_dx, coeffs, prod, tmp) != 0) {
			goto cleanup;
		}

		ep_norm(witness_points[i], witness_points[i]);
		if (ep_cmp(expected_ep, witness_points[i]) != RLC_EQ) {
			goto cleanup;
		}
	}

	ep_write_bin(recovered_witness, point_size, recovered_ep, 1);
	status = 0;

	cleanup:
		bn_free(x);
		bn_free(tmp);
		bn_free(prod);
		ep_free(recovered_ep);
		ep_free(expected_ep);

		free_bn_array_local(xs, n_witnesses);
		free_bn_array_local(weights, basis_size);
		free_bn_array_local(dx, basis_size);
		free_bn_array_local(inv_dx, basis_size);
		free_bn_array_local(coeffs, basis_size);
		free_ep_array_local(witness_points, n_witnesses);

	return status;
}

int jna_verify_same_secret_evaluation_at_ped(uint8_t *x, int n_commitments,
	uint8_t *commitments, uint8_t *witnesses, uint8_t *blinding_shares) {
	if (x == NULL || n_commitments < 0 ||
		(n_commitments > 0 && (commitments == NULL || witnesses == NULL || blinding_shares == NULL))) {
		return -1;
	}

	if (n_commitments <= 1) {
		return 1;
	}

	int status = -1;

	bn_t x_bn;
	bn_t first_blinding;
	bn_t current_blinding;
	bn_t blinding_delta;

	ep2_t x_g2;
	ep2_t alpha_minus_x_g2;

	ep_t first_commitment;
	ep_t first_witness;
	ep_t current_commitment;
	ep_t current_witness;

	ep_t pairing_g1[2];
	ep2_t pairing_g2[2];

	fp12_t pairing_result;
	fp12_t blinding_factor;

	bn_null(x_bn);
	bn_null(first_blinding);
	bn_null(current_blinding);
	bn_null(blinding_delta);

	ep2_null(x_g2);
	ep2_null(alpha_minus_x_g2);

	ep_null(first_commitment);
	ep_null(first_witness);
	ep_null(current_commitment);
	ep_null(current_witness);

	fp12_null(pairing_result);
	fp12_null(blinding_factor);

	bn_new(x_bn);
	bn_new(first_blinding);
	bn_new(current_blinding);
	bn_new(blinding_delta);

	ep2_new(x_g2);
	ep2_new(alpha_minus_x_g2);

	ep_new(first_commitment);
	ep_new(first_witness);
	ep_new(current_commitment);
	ep_new(current_witness);

	fp12_new(pairing_result);
	fp12_new(blinding_factor);

	for (int i = 0; i < 2; i++) {
		ep_null(pairing_g1[i]);
		ep_new(pairing_g1[i]);

		ep2_null(pairing_g2[i]);
		ep2_new(pairing_g2[i]);
	}

	bn_read_bin(x_bn, x, scalar_size);
	bn_mod(x_bn, x_bn, sub_prime_field);

	ep2_mul_gen(x_g2, x_bn);
	ep2_sub(alpha_minus_x_g2, gAlpha, x_g2);

	ep2_copy(pairing_g2[0], g2_base);
	ep2_copy(pairing_g2[1], alpha_minus_x_g2);

	read_g1_point(first_commitment, commitments);
	read_g1_point(first_witness, witnesses);

	bn_read_bin(first_blinding, blinding_shares, scalar_size);
	bn_mod(first_blinding, first_blinding, sub_prime_field);

	for (int i = 1; i < n_commitments; i++) {
		read_g1_point(current_commitment, &commitments[i * point_size]);
		read_g1_point(current_witness, &witnesses[i * point_size]);

		bn_read_bin(current_blinding, &blinding_shares[i * scalar_size], scalar_size);
		bn_mod(current_blinding, current_blinding, sub_prime_field);

		/*
		* lhs_i / lhs_0:
		*
		*   e(C_i - C_0, g2) * e(W_0 - W_i, alpha_minus_x_g2)
		*
		* For Pedersen KZG:
		*
		*   lhs_i = e(g, g2)^p_i(x) * e(h, g2)^r_i(x)
		*
		* Remove the blinding difference by multiplying by:
		*
		*   e(h, g2)^(r_0(x) - r_i(x))
		*
		* The final result is e(g, g2)^(p_i(x) - p_0(x)).
		* It is 1 iff both secret evaluations are equal.
		*/
		ep_sub(pairing_g1[0], current_commitment, first_commitment);
		ep_sub(pairing_g1[1], first_witness, current_witness);

		pp_map_sim_oatep_k12(pairing_result, pairing_g1, pairing_g2, 2);

		bn_sub(blinding_delta, first_blinding, current_blinding);
		bn_mod(blinding_delta, blinding_delta, sub_prime_field);

		fp12_exp(blinding_factor, hPairing, blinding_delta);
		fp12_mul(pairing_result, pairing_result, blinding_factor);

		if (fp12_cmp_dig(pairing_result, 1) != RLC_EQ) {
			status = 0;
			goto cleanup;
		}
	}

	status = 1;

	cleanup:
		for (int i = 0; i < 2; i++) {
			ep_free(pairing_g1[i]);
			ep2_free(pairing_g2[i]);
		}

		fp12_free(blinding_factor);
		fp12_free(pairing_result);

		ep_free(current_witness);
		ep_free(current_commitment);
		ep_free(first_witness);
		ep_free(first_commitment);

		ep2_free(alpha_minus_x_g2);
		ep2_free(x_g2);

		bn_free(blinding_delta);
		bn_free(current_blinding);
		bn_free(first_blinding);
		bn_free(x_bn);

	return status;
}