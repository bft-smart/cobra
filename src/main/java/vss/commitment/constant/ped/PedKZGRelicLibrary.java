package vss.commitment.constant.ped;

import com.sun.jna.Library;
import com.sun.jna.Native;

public interface PedKZGRelicLibrary extends Library {
	PedKZGRelicLibrary INSTANCE = Native.load("ped_kzg_commitments", PedKZGRelicLibrary.class);

	int jna_initialize(int threshold, byte[] alpha, int alpha_length);

	void jna_clean();

	int jna_scalar_size();

	int jna_prime_size();

	int jna_g1_size();

	int jna_get_sub_prime_field(byte[] sub_prime_field_out);

	int jna_get_prime_field(byte[] prime_field_out);

	int jna_commit_and_create_witnesses_ped(byte[] secret_coefficients, byte[] blinding_coefficients,
											byte[] shareholders, int n_shareholders,
											byte[] additional_shareholders, int n_additional_shareholders,
											byte[] commitment, byte[] witnesses, byte[] additional_witnesses);

	int jna_verify_share_ped(byte[] shareholder, byte[] secret_share, byte[] blinding_share, byte[] commitment, byte[] witness);

	int jna_add_points(byte[] points, int length, byte[] result);

	int jna_subtract_points(byte[] points_a, byte[] points_b, byte[] result);

	int jna_add_constant_to_point(byte[] commitment, byte[] constant, byte[] result);

	int jna_multiply_point_by_constant(byte[] point, byte[] constant, byte[] result);

	int jna_multiply_commitment_by_constant(byte[] commitment, int n_witnesses, byte[] witnesses, byte[] constant,
											byte[] commitment_result, byte[] witnesses_result);

	int jna_recover_witness(byte[] recovering_shareholder, int n_witnesses, byte[] shareholders, byte[] witnesses,
							byte[] recovered_witness);

	int jna_verify_same_secret_evaluation_at_ped(byte[] x, int n_commitments, byte[] commitments, byte[] witnesses,
												 byte[] blinding_shares);
}