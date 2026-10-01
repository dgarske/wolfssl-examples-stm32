/* main.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/*
 * Unified entry point for the STM32U385RG demo. Three modes are gated by
 * build-time macros:
 *
 *   !NO_CRYPT_TEST       run wolfcrypt_test() (links wolfcrypt/test/test.c)
 *   !NO_CRYPT_BENCHMARK  run benchmark_test() (links wolfcrypt/benchmark/benchmark.c)
 *   WOLFMQTT_DEMO        run wolfMQTT TLS 1.3 mTLS client over USART1
 *
 * The Makefile selects exactly one mode per TARGET (test|bench|app), but the
 * same source file is reused. Output goes to ARM semihosting in all modes.
 */

#include "stm32u3xx_hal.h"
#include <stdio.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/version.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/wc_port.h"

#ifndef NO_CRYPT_TEST
    #include "wolfcrypt/test/test.h"
#endif

#ifndef NO_CRYPT_BENCHMARK
    int benchmark_test(void *args);
#endif

#ifdef HAVE_FIPS
    #include "wolfssl/wolfcrypt/fips_test.h"
    #include "wolfssl/wolfcrypt/error-crypt.h"
#endif

#ifdef WOLFMQTT_DEMO
    #include "wolfssl/ssl.h"
    #include "wolfmqtt/mqtt_client.h"
    #include "uart_net.h"
    #include "certs.h"
    #ifdef DEMO_DHUK_CLIENT_KEY
        #include "dhuk_key.h"
    #endif
    extern void UartNet_HW_Init(void);
#endif

extern void hw_init(void);
extern void semihost_init(void);

#ifndef BUILD_CONFIG_NAME
#define BUILD_CONFIG_NAME "unknown"
#endif

/* ------------------------------------------------------------------ */
/* FIPS in-core integrity callback                                    */
/* ------------------------------------------------------------------ */
#ifdef HAVE_FIPS
static void myFipsCb(int ok, int err, const char *hash)
{
    printf("%s: FIPS callback, ok = %d, err = %d\n",
           ok ? "INFO" : "ERROR", ok, err);
    printf("%s: message = %s\n",
           ok ? "INFO" : "ERROR", wc_GetErrorString(err));
    printf("%s: hash = %s\n",
           ok ? "INFO" : "ERROR", hash);

    if (err == WC_NO_ERR_TRACE(IN_CORE_FIPS_E)) {
        printf("ERROR: In core integrity hash check failure, copy above hash\n");
        printf("ERROR: into WOLFCRYPT_FIPS_CORE_HASH_VALUE in user_settings.h "
               "and rebuild\n");
    }
}
#endif

/* ------------------------------------------------------------------ */
/* Benchmark tick source — HAL_GetTick (1 ms) is enough for ops/sec   */
/* over multi-second windows.                                         */
/* ------------------------------------------------------------------ */
#ifndef NO_CRYPT_BENCHMARK
double current_time(int reset)
{
    (void)reset;
    return (double)HAL_GetTick() / 1000.0;
}
#endif

/* ------------------------------------------------------------------ */
/* wolfMQTT TLS 1.3 mTLS demo                                         */
/* ------------------------------------------------------------------ */
#ifdef WOLFMQTT_DEMO

#define MQTT_HOST       "localhost"
#define MQTT_PORT       8883
#define MQTT_CLIENT_ID  "stm32u385-demo"
#define MQTT_TOPIC_PUB  "wolf/stm32u385/telemetry"
#define MQTT_TOPIC_SUB  "wolf/stm32u385/cmd"
#define MQTT_QOS        MQTT_QOS_1
#define MQTT_KEEP_ALIVE 60
#define MQTT_CMD_TIMEOUT_MS 30000
#define MQTT_PUB_PERIOD_MS  5000

/* Verify callback — runs during chain verification. Logs failures with
 * depth/error so handshake problems are visible. Hostname verification
 * (SNI + wolfSSL_check_domain_name) is a documented follow-up; only
 * chain verification is enforced here. Returning 0 fails the handshake;
 * 1 accepts. */
static int mqtt_tls_verify_cb(int preverify, WOLFSSL_X509_STORE_CTX *store)
{
    if (!preverify) {
        printf("cert verify failed: err=%d depth=%d\n",
               store->error, store->error_depth);
        return 0;
    }
    return 1;
}

/* TLS callback — invoked by wolfMQTT before the TLS handshake. */
static int mqtt_tls_cb(MqttClient *client)
{
    int rc;
    WOLFSSL_CTX *ctx;

    printf("[tls_cb] entered\n");
    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (ctx == NULL) {
        printf("wolfSSL_CTX_new failed\n");
        return WOLFSSL_FAILURE;
    }
    printf("[tls_cb] ctx=%p\n", (void*)ctx);

    /* Restrict to TLS 1.3 with AES-256-GCM-SHA384 + P-384 */
    rc = wolfSSL_CTX_set_cipher_list(ctx, "TLS13-AES256-GCM-SHA384");
    if (rc != WOLFSSL_SUCCESS) {
        printf("set cipher list failed: %d\n", rc);
        wolfSSL_CTX_free(ctx);
        return WOLFSSL_FAILURE;
    }
    /* Restrict ECC curves to secp384r1 to match the cert chain.
     * Native wolfSSL API (no OPENSSL_EXTRA needed). */
    rc = wolfSSL_CTX_UseSupportedCurve(ctx, WOLFSSL_ECC_SECP384R1);
    if (rc != WOLFSSL_SUCCESS) {
        printf("UseSupportedCurve(P-384) failed: %d\n", rc);
        wolfSSL_CTX_free(ctx);
        return WOLFSSL_FAILURE;
    }

    /* Load CA cert (DER) */
    rc = wolfSSL_CTX_load_verify_buffer(ctx,
             DEMO_CA_CERT_BUF, DEMO_CA_CERT_SIZE,
             WOLFSSL_FILETYPE_ASN1);
    if (rc != WOLFSSL_SUCCESS) {
        printf("load CA cert failed: %d\n", rc);
        wolfSSL_CTX_free(ctx);
        return WOLFSSL_FAILURE;
    }

    /* Load client cert (DER) */
    rc = wolfSSL_CTX_use_certificate_buffer(ctx,
             DEMO_CLI_CERT_BUF, DEMO_CLI_CERT_SIZE,
             WOLFSSL_FILETYPE_ASN1);
    if (rc != WOLFSSL_SUCCESS) {
        printf("load client cert failed: %d\n", rc);
        wolfSSL_CTX_free(ctx);
        return WOLFSSL_FAILURE;
    }

#ifdef DEMO_DHUK_CLIENT_KEY
    /* Client private key lives in a DHUK-wrapped blob, not in a buffer. Must
     * follow the certificate load, which is what sets the key type and size. */
    if (dhuk_client_key_use(ctx) != 0) {
        wolfSSL_CTX_free(ctx);
        return WOLFSSL_FAILURE;
    }
#else
    /* Load client private key (DER) */
    rc = wolfSSL_CTX_use_PrivateKey_buffer(ctx,
             DEMO_CLI_KEY_BUF, DEMO_CLI_KEY_SIZE,
             WOLFSSL_FILETYPE_ASN1);
    if (rc != WOLFSSL_SUCCESS) {
        printf("load client key failed: %d\n", rc);
        wolfSSL_CTX_free(ctx);
        return WOLFSSL_FAILURE;
    }
#endif

    /* Verify peer cert + chain. Hostname check is a documented follow-up. */
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, mqtt_tls_verify_cb);

    client->tls.ctx = ctx;
    printf("[tls_cb] returning SUCCESS, ctx loaded with CA/cert/key/cipher/curve\n");
    return WOLFSSL_SUCCESS;
}

/* MQTT message callback */
static int mqtt_msg_cb(MqttClient *client, MqttMessage *msg,
                       byte msg_new, byte msg_done)
{
    (void)client;

    if (msg_new != 0) {
        printf("RX [%.*s]: ", (int)msg->topic_name_len, msg->topic_name);
    }
    printf("%.*s", (int)msg->buffer_len, msg->buffer);
    if (msg_done != 0) {
        printf("\n");
    }
    return MQTT_CODE_SUCCESS;
}

/* SUBSCRIBE and QoS>0 PUBLISH both require a non-zero packet identifier
 * ([MQTT-2.3.1-1]); wolfMQTT rejects a zero one with MQTT_CODE_ERROR_PACKET_ID. */
static word16 demo_packet_id(void)
{
    static word16 packetId;

    if (++packetId == 0) {
        packetId = 1;
    }
    return packetId;
}

static int run_mqtt_demo(void)
{
    int rc;
    MqttClient client;
    MqttNet net;
    MqttConnect connect;
    MqttSubscribe sub;
    MqttTopic topic_sub;
    MqttPublish pub;
    byte tx_buf[WOLFMQTT_MAX_PACKET_SIZE];
    byte rx_buf[WOLFMQTT_MAX_PACKET_SIZE];
    uint32_t seq = 0;
    uint32_t last_pub_tick;
    char payload[128];

    UartNet_HW_Init();

    rc = UartNet_Init(&net);
    if (rc != MQTT_CODE_SUCCESS) {
        printf("UartNet_Init failed: %d\n", rc);
        goto done;
    }

    rc = MqttClient_Init(&client, &net, mqtt_msg_cb,
                         tx_buf, sizeof(tx_buf),
                         rx_buf, sizeof(rx_buf),
                         MQTT_CMD_TIMEOUT_MS);
    if (rc != MQTT_CODE_SUCCESS) {
        printf("MqttClient_Init failed: %d\n", rc);
        goto done;
    }

    printf("Connecting to %s:%d...\n", MQTT_HOST, MQTT_PORT);
    rc = MqttClient_NetConnect(&client, MQTT_HOST, MQTT_PORT,
                               MQTT_CMD_TIMEOUT_MS, 1, mqtt_tls_cb);
    if (rc != MQTT_CODE_SUCCESS) {
        int sslErr = (client.tls.ssl != NULL) ?
            wolfSSL_get_error(client.tls.ssl, 0) : 0;
        printf("MqttClient_NetConnect failed: rc=%d sslErr=%d lastErr=%d\n",
               rc, sslErr, client.tls.lastError);
        goto done;
    }
    printf("TLS handshake OK\n");

    memset(&connect, 0, sizeof(connect));
    connect.keep_alive_sec = MQTT_KEEP_ALIVE;
    connect.client_id      = MQTT_CLIENT_ID;
    connect.clean_session  = 1;

    rc = MqttClient_Connect(&client, &connect);
    if (rc != MQTT_CODE_SUCCESS) {
        printf("MqttClient_Connect failed: %d\n", rc);
        goto disconnect;
    }
    printf("MQTT CONNECT OK\n");

    memset(&sub, 0, sizeof(sub));
    memset(&topic_sub, 0, sizeof(topic_sub));
    topic_sub.topic_filter = MQTT_TOPIC_SUB;
    topic_sub.qos          = MQTT_QOS;
    sub.packet_id   = demo_packet_id();
    sub.topic_count = 1;
    sub.topics      = &topic_sub;

    rc = MqttClient_Subscribe(&client, &sub);
    if (rc != MQTT_CODE_SUCCESS) {
        printf("MqttClient_Subscribe failed: %d\n", rc);
        goto disconnect;
    }
    printf("SUBSCRIBE ACK: %s\n", MQTT_TOPIC_SUB);

    last_pub_tick = HAL_GetTick();
    while (1) {
        if ((HAL_GetTick() - last_pub_tick) >= MQTT_PUB_PERIOD_MS) {
            int plen;
            seq++;
            plen = snprintf(payload, sizeof(payload),
                            "{\"seq\":%lu,\"uptime\":%lu}",
                            (unsigned long)seq,
                            (unsigned long)HAL_GetTick() / 1000);

            memset(&pub, 0, sizeof(pub));
            pub.topic_name  = MQTT_TOPIC_PUB;
            pub.buffer      = (byte *)payload;
            pub.total_len   = (word16)plen;
            pub.qos         = MQTT_QOS;
            pub.packet_id   = demo_packet_id();

            rc = MqttClient_Publish(&client, &pub);
            if (rc != MQTT_CODE_SUCCESS) {
                printf("PUBLISH failed: %d\n", rc);
                break;
            }
            printf("PUBLISH: %s (seq=%lu)\n", MQTT_TOPIC_PUB,
                   (unsigned long)seq);
            last_pub_tick = HAL_GetTick();
        }

        rc = MqttClient_WaitMessage(&client, 1000);
        if (rc == MQTT_CODE_ERROR_TIMEOUT) {
            rc = MQTT_CODE_SUCCESS;
        }
        if (rc != MQTT_CODE_SUCCESS) {
            printf("WaitMessage error: %d\n", rc);
            break;
        }
    }

disconnect:
    MqttClient_Disconnect(&client);
    MqttClient_NetDisconnect(&client);
done:
    MqttClient_DeInit(&client);
    UartNet_DeInit(&net);
    return rc;
}
#endif /* WOLFMQTT_DEMO */

/* ------------------------------------------------------------------ */
/* Main                                                               */
/* ------------------------------------------------------------------ */
int main(void)
{
    int ret = 0;
    const char *mode_name;

#if !defined(NO_CRYPT_TEST)
    mode_name = "wolfCrypt test";
#elif !defined(NO_CRYPT_BENCHMARK)
    mode_name = "wolfCrypt benchmark";
#elif defined(WOLFMQTT_DEMO)
    mode_name = "wolfMQTT TLS 1.3 mTLS over UART";
#else
    mode_name = "(no demo enabled)";
#endif

    hw_init();
    semihost_init();

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    printf("\n");
    printf("========================================\n");
    printf("%s - STM32U385RG (CONFIG=%s)\n", mode_name, BUILD_CONFIG_NAME);
    printf("wolfSSL version: %s\n", LIBWOLFSSL_VERSION_STRING);
    printf("SYSCLK: %lu Hz\n", (unsigned long)HAL_RCC_GetSysClockFreq());
    printf("========================================\n\n");

#ifdef HAVE_FIPS
    wolfCrypt_SetCb_fips(myFipsCb);
#endif

#ifdef WOLFMQTT_DEMO
    wolfSSL_Init();
#else
    wolfCrypt_Init();
#endif

#ifndef NO_CRYPT_TEST
    ret = wolfcrypt_test(NULL);
    printf("\nTest result: %d (%s)\n", ret, ret == 0 ? "PASS" : "FAIL");
    printf("Test complete\n");
#endif

#ifndef NO_CRYPT_BENCHMARK
    ret = benchmark_test(NULL);
    printf("\nBenchmark result: %d\n", ret);
    printf("Bench complete\n");
#endif

#ifdef WOLFMQTT_DEMO
#ifdef DEMO_DHUK_CLIENT_KEY
    ret = dhuk_client_key_provision(DEMO_CLI_KEY_BUF, DEMO_CLI_KEY_SIZE,
                                    ECC_SECP384R1);
    if (ret != 0) {
        printf("DHUK client key provisioning failed: %d\n", ret);
        while (1) { __NOP(); }
    }
#endif
    ret = run_mqtt_demo();
    printf("Demo exited (rc=%d)\n", ret);
#ifdef DEMO_DHUK_CLIENT_KEY
    dhuk_client_key_cleanup();
#endif
#endif

#ifdef WOLFMQTT_DEMO
    wolfSSL_Cleanup();
#else
    wolfCrypt_Cleanup();
#endif

    while (1) { __NOP(); }
    return ret;
}
