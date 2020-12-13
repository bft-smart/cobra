#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <jni.h>
#include "relic.h"
#include "vss_commitment_constant_Pairing.h"

int t;
ep_t *pk;
bn_t order;
bn_t fermat_exp;
ep_t g1;
ep2_t g2;
ep2_t gAlpha;
fp12_t gPairing;
fp12_t *commitmentPairing;

void initialize(int threshold) {
	t = threshold;
	//initializing library and curve
	core_init();
	ep_param_set_any_pairf();

	ep_param_print();

	int embed = ep_param_embed();
	printf("\n-- Embed: %d\n", embed);

	//fp_param_print();

	//pre-computing public data of commitment scheme
	pk = (ep_t *)malloc(sizeof(ep_t) * (t + 1));
	bn_t alpha;
	bn_null(alpha);
	bn_new(alpha);
	bn_read_str(alpha, "13", 2, 10);

	bn_null(order);
	bn_new(order);
	ep_curve_get_ord(order);

	bn_t TWO;
    bn_null(TWO);
    bn_new(TWO);
    bn_read_str(TWO, "2", 1, 10);

    bn_null(fermat_exp);
    bn_new(fermat_exp);
    bn_sub(fermat_exp, order, TWO);

    bn_free(TWO);

	bn_t j;
	bn_null(j);
	bn_new(j);
	bn_read_str(j, "0", 1, 10);

	for (int i = 0; i <= t; i++) {
		bn_t exp;
		bn_null(exp);
		bn_new(exp);
		bn_mxp_slide(exp, alpha, j, order);

		ep_null(pk[i]);
		ep_new(pk[i]);
		ep_mul_gen(pk[i], exp);
		bn_free(exp);
		bn_add_dig(j, j, 1);
	}

	//getting generatores and pre-computing pairing of it
	ep_null(g1);
	ep2_null(g2);
	ep2_null(gAlpha);
	ep_new(g1);
	ep2_new(g2);
	ep2_new(gAlpha);
	fp12_null(gPairing);
	fp12_new(gPairing);

	ep_curve_get_gen(g1);
	ep2_curve_get_gen(g2);
	pp_map_tatep_k12(gPairing, g1, g2);

	ep2_mul_gen(gAlpha, alpha);

	bn_free(alpha);
	bn_free(j);
}

void clear() {
	bn_free(order);
	bn_free(fermat_exp);
	ep_free(g1);
	ep2_free(g2);
	ep2_free(gAlpha);
	fp12_free(gPairing);
	free(pk);
	free(commitmentPairing);
	core_clean();
}

bn_t *read_number(JNIEnv *env, jbyteArray bytes) {
	jsize bin_size = (*env)->GetArrayLength(env, bytes);
	jbyte* bin = malloc(sizeof(jbyte) * bin_size);
	(*env)->GetByteArrayRegion(env, bytes, 0, bin_size, bin);
	bn_t *result = malloc(sizeof(bn_t));
	bn_null(*result);
	bn_new(*result);
	bn_read_bin(*result, bin, bin_size);

	free(bin);
	return result;
}

void throw_illegal_state_exception(JNIEnv *env, char *message) {
	char *className = "java/lang/IllegalStateException";
	jclass exClass = (*env)->FindClass(env, className);
	(*env)->ThrowNew(env, exClass, message);
}

bn_t *read_number_str(JNIEnv *env, jstring stringData) {
	const char *str = (*env)->GetStringUTFChars(env, stringData, 0);
	int size = (*env)->GetStringUTFLength(env, stringData);
	bn_t *result = malloc(sizeof(bn_t));
	bn_null(*result);
	bn_new(*result);
	bn_read_str(*result, str, size, 16);
	(*env)->ReleaseStringUTFChars(env, stringData, str);
	return result;
}

ep_t *read_point(JNIEnv *env, jbyteArray bytes) {
	err_t e;
	jsize bin_size = (*env)->GetArrayLength(env, bytes);
	jbyte *bin = malloc(sizeof(jbyte) * bin_size);
	(*env)->GetByteArrayRegion(env, bytes, 0, bin_size, bin);
	ep_t *result = malloc(sizeof(ep_t));
	ep_null(*result);
	ep_new(*result);
	TRY {
		ep_read_bin(*result, bin, bin_size);
	} CATCH(e) {
		printf("ERROR!!!!\n");
		return NULL;
	}
	free(bin);
	return result;
}

ep_t *compute_commitment_witness(int t, JNIEnv *env, jobjectArray coefficientsBytes) {
	ep_t *result = malloc(sizeof(ep_t));
	ep_null(*result);
	ep_new(*result);
	ep_set_infty(*result);

	for (int i = 0; i <= t; i++) {
		int gIndex = t - i;
		jstring arr = (*env)->GetObjectArrayElement(env, coefficientsBytes, i);
		bn_t *coef = read_number_str(env, arr);

		ep_t temp;
		ep_null(temp);
		ep_new(temp);

		ep_mul_slide(temp, pk[gIndex], *coef);

		ep_add_basic(*result, *result, temp);
		free(coef);
		ep_free(temp);
	}

	return result;
}

jbyteArray convert_point_to_bytes(JNIEnv *env, ep_t *value) {
	int bin_size = ep_size_bin(*value, 1);
	uint8_t *bin = malloc(sizeof(uint8_t) * bin_size);
	ep_write_bin(bin, bin_size, *value, 1);
	jbyteArray result = (*env)->NewByteArray(env, bin_size);
	(*env)->SetByteArrayRegion(env, result, 0, bin_size, bin);
	free(bin);
	return result;
}

jbyteArray convert_fp12_to_bytes(JNIEnv *env, fp12_t *value) {
    int bin_size = fp12_size_bin(*value, 1);
    uint8_t *bin = malloc(sizeof(uint8_t) * bin_size);
    fp12_write_bin(bin, bin_size, *value, 1);
    jbyteArray result = (*env)->NewByteArray(env, bin_size);
    (*env)->SetByteArrayRegion(env, result, 0, bin_size, bin);
    free(bin);
    return result;
}

bn_t *bn_custom_div(bn_t dividend, bn_t divisor) {
	bn_t *result = malloc(sizeof(bn_t));
	bn_null(*result);
	bn_new(*result);
	bn_t d;
	bn_null(d);
	bn_new(d);

	bn_mxp_slide(d, divisor, fermat_exp, order);

	bn_mul(*result, dividend, d);
	bn_mod_basic(*result, *result, order);

	return result;
}

bn_t *bn_custom_invert(bn_t number) {
	bn_t *result = malloc(sizeof(bn_t));
	bn_null(*result);
	bn_new(*result);
	bn_mxp_slide(*result, number, fermat_exp, order);
	return result;
}

JNIEXPORT void JNICALL Java_vss_commitment_constant_Pairing_initialize(JNIEnv *env, jobject obj, jint t) {
	initialize(t);
}

JNIEXPORT jbyteArray JNICALL Java_vss_commitment_constant_Pairing_getOrderBytes(JNIEnv *env, jobject obj) {
	int nBytes = bn_size_bin(order);
	uint8_t* bytes = malloc(sizeof(uint8_t) * nBytes);
	bn_write_bin(bytes, nBytes, order);

	jbyteArray result = (*env)->NewByteArray(env, nBytes);
	(*env)->SetByteArrayRegion(env, result, 0, nBytes, bytes);
	free(bytes);
	return result;
}


JNIEXPORT jbyteArray JNICALL Java_vss_commitment_constant_Pairing_commit(JNIEnv *env, jobject obj, 
	jobjectArray coefficientsBytes) {
	ep_t *commitment = compute_commitment_witness(t, env, coefficientsBytes);
	
	jbyteArray result = convert_point_to_bytes(env, commitment);
	free(commitment);
	return result;
}

JNIEXPORT jbyteArray JNICALL Java_vss_commitment_constant_Pairing_createWitness(JNIEnv *env, jobject obj, 
	jobjectArray coefficientsBytes) {
	ep_t *witness = compute_commitment_witness(t - 1, env, coefficientsBytes);
	jbyteArray result =  convert_point_to_bytes(env, witness);
	free(witness);
	return result;
}

JNIEXPORT jbyteArray JNICALL Java_vss_commitment_constant_Pairing_computePartialVerification (JNIEnv *env, jobject obj,
    jbyteArray xBytes, jbyteArray commitmentBytes, jbyteArray witnessBytes) {
    ep_t *witness = read_point(env, witnessBytes);
    if (witness == NULL) {
        throw_illegal_state_exception(env, "Witness is incorrect");
        return false;
    }
    ep_t *commitment = read_point(env, commitmentBytes);
    if (commitment == NULL) {
        throw_illegal_state_exception(env, "Commitment is incorrect");
        return false;
    }
    bn_t *i = read_number(env, xBytes);

    fp12_t eCommitment, eWitness, eWitnessInv;
    fp12_null(eCommitment);
    fp12_null(eWitness);
    fp12_null(eWitnessInv);
    fp12_new(eCommitment);
    fp12_new(eWitness);
    fp12_new(eWitnessInv);

    ep2_t gI, gAlphaI;
    ep2_null(gI);
    ep2_null(gAlphaI);
    ep2_new(gI);
    ep2_new(gAlphaI);

    ep2_mul_gen(gI, *i);
    ep2_sub_basic(gAlphaI, gAlpha, gI);

    pp_map_tatep_k12(eWitness, *witness, gAlphaI);
    pp_map_tatep_k12(eCommitment, *commitment, g2);

    fp12_inv(eWitnessInv, eWitness);

    fp12_t *result = malloc(sizeof(fp12_t));
    fp12_null(*result);
    fp12_new(*result);

    fp12_mul_basic(*result, eCommitment, eWitnessInv);

    jbyteArray finalResult = convert_fp12_to_bytes(env, result);

    fp12_free(*result);
    free(result);

    ep_free(*witness);
    ep_free(*commitment);
    bn_free(*i);
    ep2_free(gI);
    ep2_free(gAlphaI);
    fp12_free(eWitness);
    fp12_free(eWitnessInv);
    fp12_free(eCommitment);

    free(witness);
    free(commitment);
    free(i);
    return finalResult;
}

JNIEXPORT jboolean JNICALL Java_vss_commitment_constant_Pairing_verify(JNIEnv *env, jobject obj, 
	jbyteArray xBytes, jbyteArray yBytes, jbyteArray witnessBytes) {
	ep_t *witness = read_point(env, witnessBytes);
	if (witness == NULL) {
		throw_illegal_state_exception(env, "Witness is incorrect");
		return false;
	}
	bn_t *i = read_number(env, xBytes);
	bn_t *share = read_number(env, yBytes);

	fp12_t sharePairing, witnessPairing, righSide;
	fp12_null(sharePairing);
	fp12_null(witnessPairing);
	fp12_null(righSide);
	fp12_new(sharePairing);
	fp12_new(witnessPairing);
	fp12_new(righSide);
	
	ep2_t gI, gAlphaI;
	ep2_null(gI);
	ep2_null(gAlphaI);
	ep2_new(gI);
	ep2_new(gAlphaI);
	
	ep2_mul_gen(gI, *i);
	ep2_sub_basic(gAlphaI, gAlpha, gI);

	pp_map_tatep_k12(witnessPairing, *witness, gAlphaI);
	fp12_exp(sharePairing, gPairing, *share);

	fp12_mul_basic(righSide, witnessPairing, sharePairing);

	int cmp = fp12_cmp(*commitmentPairing, righSide);

	fp12_free(sharePairing);
	fp12_free(witnessPairing);
	fp12_free(righSide);
	ep2_free(gI);
	ep2_free(gAlphaI);
	free(witness);
	free(i);
	free(share);

	return cmp == 0;
}

JNIEXPORT void JNICALL Java_vss_commitment_constant_Pairing_endVerification(JNIEnv *env, jobject obj) {
	fp12_free(*commitmentPairing);
	free(commitmentPairing);
	commitmentPairing = NULL;
}

JNIEXPORT void JNICALL Java_vss_commitment_constant_Pairing_startVerification(JNIEnv *env, jobject obj, 
	jbyteArray commitmentBytes) {
	ep_t *commitment = read_point(env, commitmentBytes);
	if (commitment == NULL) {
		throw_illegal_state_exception(env, "Commitment is incorrect");
		return;
	}
	commitmentPairing = malloc(sizeof(fp12_t));
	fp12_null(*commitmentPairing);
	fp12_new(*commitmentPairing);

	pp_map_tatep_k12(*commitmentPairing, *commitment, g2);

	ep_free(*commitment);
	free(commitment);
}

JNIEXPORT jbyteArray JNICALL Java_vss_commitment_constant_Pairing_multiplyValues(JNIEnv *env, jobject obj, jobjectArray valuesBytes) {
	jsize nValues = (*env)->GetArrayLength(env, valuesBytes);
	
	ep_t *sum = malloc(sizeof(ep_t));
	ep_null(*sum);
	ep_new(*sum);
	ep_set_infty(*sum);

	for (int i = 0; i < nValues; i++) {
		jbyteArray valueBytes = (*env)->GetObjectArrayElement(env, valuesBytes, i);
		ep_t *value = read_point(env, valueBytes);

		if (value == NULL) {
			throw_illegal_state_exception(env, "Value is incorrect");
			return NULL;
		}

		ep_add_basic(*sum, *sum, *value);
		free(value);
	}

	jbyteArray result = convert_point_to_bytes(env, sum);
	free(sum);
	return result;
}

JNIEXPORT jbyteArray JNICALL Java_vss_commitment_constant_Pairing_divideValues(JNIEnv *env, jobject obj, jbyteArray v1, jbyteArray v2) {
    ep_t *a = read_point(env, v1);
    ep_t *b = read_point(env, v2);

    ep_t *r = malloc(sizeof(ep_t));
	ep_null(*r);
	ep_new(*r);

	ep_sub_basic(*r, *a, *b);

	free(a);
	free(b);

	jbyteArray result = convert_point_to_bytes(env, r);
	free(r);

	return result;
}


bn_t *multiply_polynomials(bn_t *values_1, bn_t *values_2, int n_values_1, int n_values_2) {
	int len = n_values_1 + n_values_2 - 1;
	bn_t *result = malloc(sizeof(bn_t) * len);
	for(int i = 0; i < len; i++) {
		bn_new(result[i]);
		bn_null(result[i]);
		bn_zero(result[i]);
	}

	bn_t temp;
	bn_null(temp);
	bn_new(temp);

	for (int i = 0; i < n_values_1; i++) {
		for (int j = 0; j < n_values_2; j++) {
			bn_mul_karat(temp, values_1[i], values_2[j]);
			bn_add(result[i + j], result[i + j], temp);
			bn_mod_basic(result[i + j], result[i + j], order);
		}
	}

	return result;
}

/*
* len_1 >= len_2
*/
void add_polynomials(ep_t *polynomial_1, ep_t *polynomial_2, int len_1, int len_2) {
	for (int i = len_1 - 1, j = len_2 - 1; j >= 0; i--, j--) {
		ep_add_basic(polynomial_1[i], polynomial_1[i], polynomial_2[j]);
	}
}

ep_t *evaluate_polynomial_at(bn_t x, ep_t *polynomial, int degree) {
	ep_t *result = malloc(sizeof(ep_t));
	ep_null(*result);
	ep_new(*result);
	ep_copy(*result, polynomial[0]);
	
	for (int i = 1; i < degree; i++) {
		ep_mul_slide(*result, *result, x);
		ep_add_basic(*result, polynomial[i], *result);
	}

	return result;
}

int compute_polynomial_degree(ep_t *polynomial, int len) {
	int degree = len - 1;
	for (int i = 0; i < len; i++)
	{
		if (ep_is_infty(polynomial[i]) == 0)
			return degree;
		degree--;
	}

	return degree;
}

ep_t *compute_polynomial(bn_t *x, bn_t *xs[], ep_t *ys[], int n_points) {
	if (n_points == 1)
		return ys[0];
	bn_t denominator, temp;
	bn_null(denominator);
	bn_null(temp);
	bn_new(denominator);
	bn_new(temp);


	ep_t *polynomial = NULL;
	for (int i = 0; i < n_points; i++) {
		bn_read_str(denominator, "1", 1, 2);
		bn_t *numerator = NULL;
		int numerator_size = 1;
		for (int m = 0; m < n_points; m++) {
			if (i == m)
				continue;
			bn_t *current_numerator = malloc(sizeof(bn_t) * 2);
			bn_null(current_numerator[0]);
			bn_null(current_numerator[1]);
			bn_new(current_numerator[0]);
			bn_new(current_numerator[1]);
			bn_read_str(current_numerator[0], "1", 1, 2);
			bn_copy(current_numerator[1], *xs[m]);
			bn_neg(current_numerator[1], current_numerator[1]);
			if (numerator == NULL) {
				numerator = current_numerator;
				numerator_size = 2;
			} else {
				numerator = multiply_polynomials(numerator, current_numerator, numerator_size, 2);
				numerator_size = numerator_size + 1;
				free(current_numerator);
			}


			bn_sub(temp, *xs[i], *xs[m]);
			bn_mul_karat(denominator, denominator, temp);
			bn_mod_basic(denominator, denominator, order);
		}

		bn_t *d_inverted = bn_custom_invert(denominator);
		numerator = multiply_polynomials(numerator, d_inverted, numerator_size, 1);
		ep_t *li = malloc(sizeof(ep_t) * n_points);
		for (int j = 0; j < n_points; j++) {
			ep_mul_slide(li[j], *ys[i], numerator[j]);
		}

		free(numerator);

		if (polynomial == NULL) {
			polynomial = li;
		} else {
			add_polynomials(polynomial, li, n_points, n_points);
		}
	}

	ep_t *w1 = evaluate_polynomial_at(*x, polynomial, n_points);

	int degree = compute_polynomial_degree(polynomial, n_points);
	if (degree != t - 1) {
		return NULL;
	}
	return w1;
}

JNIEXPORT jbyteArray JNICALL Java_vss_commitment_constant_Pairing_interpolateAndEvaluateAt
(JNIEnv *env, jobject obj, jbyteArray xBytes, jobjectArray valuesBytes) {
    jsize nValues = (*env)->GetArrayLength(env, valuesBytes);

	bn_t *x = read_number(env, xBytes);

	bn_t *xs[nValues];
	ep_t *ys[nValues];


	for(int i = 0; i < nValues; i++) {
		jobjectArray valueBytes = (*env)->GetObjectArrayElement(env, valuesBytes, i);
		jbyteArray xValueBytes = (*env)->GetObjectArrayElement(env, valueBytes, 0);
		jbyteArray yValueBytes = (*env)->GetObjectArrayElement(env, valueBytes, 1);

		bn_t *xValue = read_number(env, xValueBytes);
		ep_t *yValue = read_point(env, yValueBytes);
		if (yValue == NULL) {
			throw_illegal_state_exception(env, "Witness is incorrect");
			return NULL;
		}
		ys[i] = yValue;
		xs[i] = xValue;
	}
	
	ep_t *recovered_witness = compute_polynomial(x, xs, ys, nValues);

	if (recovered_witness == NULL) {
		throw_illegal_state_exception(env, "Witness recovery polynomial degree is incorrect");
		return NULL;
	}

	/*ep_t y;
	ep_null(y);
	ep_new(y);
	ep_set_infty(y);
	bn_t d, n;
	bn_null(d);
	bn_null(n);
	bn_new(d);
	bn_new(n);
	bn_t temp;
	bn_null(temp);
	bn_new(temp);
	ep_t ls;
	ep_null(ls);
	ep_new(ls);

	for (int i = 0; i < nValues; i++) {
		bn_read_str(n, "1", 1, 10);
		bn_read_str(d, "1", 1, 10);

		for (int j = 0; j < nValues; j++) {
			if (i == j)
				continue;

			bn_sub(temp, *x, *xs[j]);
			bn_mul(n, n, temp);
			bn_sub(temp, *xs[i], *xs[j]);
			bn_mul(d, d, temp);
		}

		bn_t *l = bn_custom_div(n, d);

		ep_mul_slide(ls, *ys[i], *l);

		bn_free(*l);
		free(l);

		ep_add_basic(y, y, ls);
	}

	for (int i = 0; i < nValues; i++) {
		free(ys[i]);
		free(xs[i]);
	}*/
	return convert_point_to_bytes(env, recovered_witness);
}

JNIEXPORT void JNICALL Java_vss_commitment_constant_Pairing_close(JNIEnv *env, jobject obj) {
	clear();
}