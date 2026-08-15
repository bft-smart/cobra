#ifndef PED_KZG_COMMITMENTS_LIB_H
#define PED_KZG_COMMITMENTS_LIB_H

int jna_initialize(int threshold, uint8_t *alpha, int alpha_length);

int jna_scalar_size();

int jna_prime_size();

int jna_g1_size();

int jna_get_sub_prime_field(uint8_t *sub_prime_field_out);

int jna_get_prime_field(uint8_t *prime_field_out);

void jna_clean();

int jna_commit_and_create_witnesses_ped(uint8_t *secret_coefficients, uint8_t *blinding_coefficients,
                                    	uint8_t *shareholders, int n_shareholders,
                                    	uint8_t *additional_shareholders, int n_additional_shareholders,
                                    	uint8_t *commitment, uint8_t *witnesses, uint8_t *additional_witnesses);

int jna_verify_share_ped(uint8_t *shareholder, uint8_t *secret_share, uint8_t *blinding_share, uint8_t *commitment,
						uint8_t *witness);

int jna_add_points(uint8_t *points, int length, uint8_t *result);

//Returns point_a - point_b
int jna_subtract_points(uint8_t *point_a, uint8_t *point_b, uint8_t *result);

int jna_add_constant_to_point(uint8_t *point, uint8_t *constant, uint8_t *result);

int jna_multiply_point_by_constant(uint8_t *point, uint8_t *constant, uint8_t *result);

int jna_multiply_commitment_by_constant(uint8_t *commitment, int n_witnesses, uint8_t *witnesses, uint8_t *constant,
										uint8_t *commitment_result, uint8_t *witnesses_result);

int jna_recover_witness(uint8_t *recovering_shareholder, int n_witnesses, uint8_t *shareholders, uint8_t *witnesses,
						uint8_t *recovered_witness);

int jna_verify_same_secret_evaluation_at_ped(uint8_t *x, int n_commitments, uint8_t *commitments, uint8_t *witnesses,
											uint8_t *blinding_shares);

#endif