#include <stdio.h>
#include <stdlib.h>
#include <jni.h>
#include "relic.h"
#include "vss_commitment_constant_Pairing.h"

int t;
ep_t *pk;
bn_t order;
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

ep_t *read_point(JNIEnv *env, jbyteArray bytes) {
	jsize bin_size = (*env)->GetArrayLength(env, bytes);
	jbyte *bin = malloc(sizeof(jbyte) * bin_size);
	(*env)->GetByteArrayRegion(env, bytes, 0, bin_size, bin);
	ep_t *result = malloc(sizeof(ep_t));
	ep_null(*result);
	ep_new(*result);
	ep_read_bin(*result, bin, bin_size);
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
		jbyteArray arr = (*env)->GetObjectArrayElement(env, coefficientsBytes, i);
		bn_t *coef = read_number(env, arr);

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

JNIEXPORT jboolean JNICALL Java_vss_commitment_constant_Pairing_verify(JNIEnv *env, jobject obj, 
	jbyteArray xBytes, jbyteArray yBytes, jbyteArray witnessBytes) {
	ep_t *witness = read_point(env, witnessBytes);
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

		ep_add_basic(*sum, *sum, *value);
		free(value);
	}

	jbyteArray result = convert_point_to_bytes(env, sum);
	free(sum);
	return result;
}

JNIEXPORT void JNICALL Java_vss_commitment_constant_Pairing_close(JNIEnv *env, jobject obj) {
	clear();
}