/* awsiot.c
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
 *
 * This file is part of wolfMQTT.
 *
 * wolfMQTT is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfMQTT is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* Include the autoconf generated config.h */
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include "wolfmqtt/mqtt_client.h"


/* This example only works with ENABLE_MQTT_TLS (wolfSSL library) */
#if defined(ENABLE_MQTT_TLS)
    #if !defined(WOLFSSL_USER_SETTINGS) && !defined(USE_WINDOWS_API)
        #include <wolfssl/options.h>
    #endif
    #include <wolfssl/wolfcrypt/settings.h>
    #include <wolfssl/version.h>

    #undef  ENABLE_AWSIOT_EXAMPLE
    #define ENABLE_AWSIOT_EXAMPLE
#endif


#ifdef ENABLE_AWSIOT_EXAMPLE

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/hmac.h>

#include "awsiot.h"
#include "examples/mqttexample.h"
#include "examples/mqttnet.h"
#include <wolfmqtt/version.h>

/* Locals */
static int mStopRead = 0;

/* Configuration */
#define APP_HARDWARE         "wolf_aws_iot_demo"
#define APP_FIRMWARE_VERSION LIBWOLFMQTT_VERSION_STRING

#define MAX_BUFFER_SIZE         512    /* Maximum size for network read/write callbacks */
#define AWSIOT_HOST             "a2dujmi05ideo2.iot.us-west-2.amazonaws.com"
#define AWSIOT_DEVICE_ID        "demoDevice"
#define AWSIOT_QOS              MQTT_QOS_1
#define AWSIOT_KEEP_ALIVE_SEC   DEFAULT_KEEP_ALIVE_SEC
#define AWSIOT_CMD_TIMEOUT_MS   DEFAULT_CMD_TIMEOUT_MS

#define AWSIOT_SUBSCRIBE_TOPIC  "$aws/things/" AWSIOT_DEVICE_ID "/shadow/update/delta"
#define AWSIOT_PUBLISH_TOPIC    "$aws/things/" AWSIOT_DEVICE_ID "/shadow/update"

#define AWSIOT_PUBLISH_MSG_SZ   400
#if 0
static const char* device_pub_key =
"-----BEGIN PUBLIC KEY-----\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqsAKVhbfQEWblC8Pvgub\n"
"qpJasVoCEsSfvLF4b5DIAsoMeieP26y6Vyd3njRyuigSQ6jP+mo3GyqSfeCbqfJ2\n"
"dx3BNICEk7P46Bu37ewoI24pScnT+5Rcfw//dh8WHDq0d0933i4vOKEKA6ft51Ax\n"
"Y6KzvNrwxo6bml0Vi2DBx3WLGw+MDiHXk2L0geSYSNjFz/u9dkgEUPhEGbNZuw2y\n"
"xhwbNfaiPe2ld5Fir6iUybuj93xfWqqNls77V6Qj7mI8pamdGFtQnkP+6l2XTa6J\n"
"bunCqZo1PURtUXch5db6rMq/6rRZrlJM7NngPI1vv8jF4T3G4mjyT8I4KxQK1s90\n"
"9QIDAQAB\n"
"-----END PUBLIC KEY-----";
#endif

static const char* root_ca = "certs/aws_ca.pem";

static const char* device_cert = "certs/aws_cert.pem";

static const char* device_priv_key =
#ifdef WOLFSSL_ENCRYPTED_KEYS
    "certs/aws_key.pkcs8";
#else
    "certs/aws_key.pem";
#endif

static int mqtt_aws_tls_verify_cb(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    char buffer[WOLFSSL_MAX_ERROR_SZ];

    PRINTF("MQTT TLS Verify Callback: PreVerify %d, Error %d (%s)", preverify,
        store->error, store->error != 0 ?
            wolfSSL_ERR_error_string(store->error, buffer) : "none");
    PRINTF("  Subject's domain name is %s", store->domain);

    if (store->error != 0) {
        /* Allowing to continue */
        /* Should check certificate and return 0 if not okay */
        PRINTF("  Allowing cert anyways");
    }

    return 1;
}

/* Use this callback to setup TLS certificates and verify callbacks */
static int mqtt_aws_tls_cb(MqttClient* client)
{
    int rc = WOLFSSL_FAILURE;

    /* Use highest available and allow downgrade. If wolfSSL is built with
     * old TLS support, it is possible for a server to force a downgrade to
     * an insecure version. */
    client->tls.ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    if (client->tls.ctx) {
        wolfSSL_CTX_set_verify(client->tls.ctx, WOLFSSL_VERIFY_PEER,
                               mqtt_aws_tls_verify_cb);

        /* Load CA certificate buffer */
        rc = wolfSSL_CTX_load_verify_locations(client->tls.ctx,
            root_ca, NULL);

        /* Load Client Cert */
        if (rc == WOLFSSL_SUCCESS)
            rc = wolfSSL_CTX_use_certificate_file(client->tls.ctx,
                device_cert, WOLFSSL_FILETYPE_PEM);

        #ifdef WOLFSSL_ENCRYPTED_KEYS
            /* Setup password callback for pkcs8 key */
            wolfSSL_CTX_set_default_passwd_cb(client->tls.ctx,
                    mqtt_password_cb);
        #endif

        /* Load Private Key */
        if (rc == WOLFSSL_SUCCESS)
            rc = wolfSSL_CTX_use_PrivateKey_file(client->tls.ctx,
                device_priv_key, WOLFSSL_FILETYPE_PEM);
    }

    PRINTF("MQTT TLS Setup (%d)", rc);

    return rc;
}

static int mqtt_message_cb(MqttClient *client, MqttMessage *msg,
    byte msg_new, byte msg_done)
{
    MQTTCtx* mqttCtx = (MQTTCtx*)client->ctx;
    byte buf[PRINT_BUFFER_SIZE+1];
    word32 len;

    (void)mqttCtx;

    if (msg_new) {
        /* Determine min size to dump */
        len = msg->topic_name_len;
        if (len > PRINT_BUFFER_SIZE) {
            len = PRINT_BUFFER_SIZE;
        }
        XMEMCPY(buf, msg->topic_name, len);
        buf[len] = '\0'; /* Make sure its null terminated */

        /* Print incoming message */
        PRINTF("MQTT Message: Topic %s, Qos %d, Len %u",
            buf, msg->qos, msg->total_len);
    }

    /* Print message payload */
    len = msg->buffer_len;
    if (len > PRINT_BUFFER_SIZE) {
        len = PRINT_BUFFER_SIZE;
    }
    XMEMCPY(buf, msg->buffer, len);
    buf[len] = '\0'; /* Make sure its null terminated */
    PRINTF("Payload (%d - %d) printing %d bytes:" LINE_END "%s",
        msg->buffer_pos, msg->buffer_pos + msg->buffer_len, len, buf);

    if (msg_done) {
        PRINTF("MQTT Message: Done");
    }

    /* Return negative to terminate publish processing */
    return MQTT_CODE_SUCCESS;
}

int awsiot_test(MQTTCtx *mqttCtx)
{
    int rc = MQTT_CODE_SUCCESS, i;

    switch (mqttCtx->stat)
    {
        case WMQ_BEGIN:
        {
            PRINTF("AwsIoT Client: QoS %d, Use TLS %d", mqttCtx->qos, mqttCtx->use_tls);

            /* Aws IoT requires TLS */
            if (!mqttCtx->use_tls) {
                return MQTT_CODE_ERROR_BAD_ARG;
            }
        }
        FALL_THROUGH;

        case WMQ_NET_INIT:
        {
            mqttCtx->stat = WMQ_NET_INIT;

            /* Initialize Network */
            rc = MqttClientNet_Init(&mqttCtx->net, mqttCtx);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }
            PRINTF("MQTT Net Init: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                goto exit;
            }

            /* setup tx/rx buffers */
            mqttCtx->tx_buf = (byte*)WOLFMQTT_MALLOC(MAX_BUFFER_SIZE);
            mqttCtx->rx_buf = (byte*)WOLFMQTT_MALLOC(MAX_BUFFER_SIZE);
        }
        FALL_THROUGH;

        case WMQ_INIT:
        {
            mqttCtx->stat = WMQ_INIT;

            /* Initialize MqttClient structure */
            rc = MqttClient_Init(&mqttCtx->client, &mqttCtx->net, mqtt_message_cb,
                mqttCtx->tx_buf, MAX_BUFFER_SIZE, mqttCtx->rx_buf, MAX_BUFFER_SIZE,
                mqttCtx->cmd_timeout_ms);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }
            PRINTF("MQTT Init: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                goto exit;
            }
            mqttCtx->client.ctx = mqttCtx;

        #ifdef WOLFMQTT_V5
            /* AWS broker only supports v3.1.1 client */
            mqttCtx->client.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_4;
        #endif

        }
        FALL_THROUGH;

        case WMQ_TCP_CONN:
        {
            mqttCtx->stat = WMQ_TCP_CONN;

            /* Connect to broker */
            rc = MqttClient_NetConnect(&mqttCtx->client, mqttCtx->host, mqttCtx->port,
                DEFAULT_CON_TIMEOUT_MS, mqttCtx->use_tls, mqtt_aws_tls_cb);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }
            PRINTF("MQTT Socket Connect: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                goto exit;
            }

            /* Build connect packet */
            XMEMSET(&mqttCtx->connect, 0, sizeof(MqttConnect));
            mqttCtx->connect.keep_alive_sec = mqttCtx->keep_alive_sec;
            mqttCtx->connect.clean_session = mqttCtx->clean_session;
            mqttCtx->connect.client_id = mqttCtx->client_id;

            /* Last will and testament sent by broker to subscribers
                of topic when broker connection is lost */
            XMEMSET(&mqttCtx->lwt_msg, 0, sizeof(mqttCtx->lwt_msg));
            mqttCtx->connect.lwt_msg = &mqttCtx->lwt_msg;
            mqttCtx->connect.enable_lwt = mqttCtx->enable_lwt;
            if (mqttCtx->enable_lwt) {
                /* Send client id in LWT payload */
                mqttCtx->lwt_msg.qos = mqttCtx->qos;
                mqttCtx->lwt_msg.retain = 0;
                mqttCtx->lwt_msg.topic_name = AWSIOT_PUBLISH_TOPIC"lwt";
                mqttCtx->lwt_msg.buffer = (byte*)mqttCtx->client_id;
                mqttCtx->lwt_msg.total_len = (word16)XSTRLEN(mqttCtx->client_id);
            }
            /* Optional authentication */
            mqttCtx->connect.username = mqttCtx->username;
            mqttCtx->connect.password = mqttCtx->password;
        }
        FALL_THROUGH;

        case WMQ_MQTT_CONN:
        {
            mqttCtx->stat = WMQ_MQTT_CONN;

            /* Send Connect and wait for Connect Ack */
            rc = MqttClient_Connect(&mqttCtx->client, &mqttCtx->connect);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }
            PRINTF("MQTT Connect: Proto (%s), %s (%d)",
                MqttClient_GetProtocolVersionString(&mqttCtx->client),
                MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                goto disconn;
            }

            /* Validate Connect Ack info */
            PRINTF("MQTT Connect Ack: Return Code %u, Session Present %d",
                mqttCtx->connect.ack.return_code,
                (mqttCtx->connect.ack.flags &
                    MQTT_CONNECT_ACK_FLAG_SESSION_PRESENT) ?
                    1 : 0
            );

            /* Build list of topics */
            mqttCtx->topics[0].topic_filter = mqttCtx->topic_name;
            mqttCtx->topics[0].qos = mqttCtx->qos;

            /* Subscribe Topic */
            XMEMSET(&mqttCtx->subscribe, 0, sizeof(MqttSubscribe));
            mqttCtx->subscribe.packet_id = mqtt_get_packetid();
            mqttCtx->subscribe.topic_count = sizeof(mqttCtx->topics)/sizeof(MqttTopic);
            mqttCtx->subscribe.topics = mqttCtx->topics;
        }
        FALL_THROUGH;

        case WMQ_SUB:
        {
            mqttCtx->stat = WMQ_SUB;

            rc = MqttClient_Subscribe(&mqttCtx->client, &mqttCtx->subscribe);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }
            PRINTF("MQTT Subscribe: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                goto disconn;
            }

            /* show subscribe results */
            for (i = 0; i < mqttCtx->subscribe.topic_count; i++) {
                MqttTopic *topic = &mqttCtx->subscribe.topics[i];
                PRINTF("  Topic %s, Qos %u, Return Code %u",
                    topic->topic_filter,
                    topic->qos, topic->return_code);
            }

            /* Publish Topic */
            XSNPRINTF((char*)mqttCtx->app_ctx, AWSIOT_PUBLISH_MSG_SZ,
                "{\"state\":{\"reported\":{\"hardware\":{\"type\":\"%s\",\"firmware_version\":\"%s\"}}}}",
                APP_HARDWARE, APP_FIRMWARE_VERSION);

            XMEMSET(&mqttCtx->publish, 0, sizeof(MqttPublish));
            mqttCtx->publish.retain = 0;
            mqttCtx->publish.qos = mqttCtx->qos;
            mqttCtx->publish.duplicate = 0;
            mqttCtx->publish.topic_name = AWSIOT_PUBLISH_TOPIC;
            mqttCtx->publish.packet_id = mqtt_get_packetid();
            mqttCtx->publish.buffer = (byte*)mqttCtx->app_ctx;
            mqttCtx->publish.total_len = (word32)XSTRLEN((char*)mqttCtx->app_ctx);
        }
        FALL_THROUGH;

        case WMQ_PUB:
        {
            mqttCtx->stat = WMQ_PUB;

            rc = MqttClient_Publish(&mqttCtx->client, &mqttCtx->publish);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }
            PRINTF("MQTT Publish: Topic %s, %s (%d)",
                mqttCtx->publish.topic_name, MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                goto disconn;
            }

            /* Read Loop */
            PRINTF("MQTT Waiting for message...");
        }
        FALL_THROUGH;

        case WMQ_WAIT_MSG:
        {
            mqttCtx->stat = WMQ_WAIT_MSG;

            do {
                /* check for test mode or stop */
                if (mStopRead || mqttCtx->test_mode) {
                    rc = MQTT_CODE_SUCCESS;
                    PRINTF("MQTT Exiting...");
                    break;
                }

                /* Try and read packet */
                rc = MqttClient_WaitMessage(&mqttCtx->client, mqttCtx->cmd_timeout_ms);

            #ifdef WOLFMQTT_NONBLOCK
                /* Track elapsed time with no activity and trigger timeout */
                rc = mqtt_check_timeout(rc, &mqttCtx->start_sec,
                    mqttCtx->cmd_timeout_ms/1000);
            #endif

                /* check return code */
                if (rc == MQTT_CODE_CONTINUE) {
                    return rc;
                }
            #ifdef WOLFMQTT_ENABLE_STDIN_CAP
                else if (rc == MQTT_CODE_STDIN_WAKE) {
                    /* Get data from STDIO */
                    XMEMSET(mqttCtx->rx_buf, 0, MAX_BUFFER_SIZE);
                    if (XFGETS((char*)mqttCtx->rx_buf, MAX_BUFFER_SIZE - 1, stdin) != NULL) {
                        /* rc = (int)XSTRLEN((char*)mqttCtx->rx_buf); */

                        /* Publish Topic */
                        XSNPRINTF((char*)mqttCtx->app_ctx, AWSIOT_PUBLISH_MSG_SZ,
                            "{\"state\":{\"reported\":{\"msg\":\"%s\"}}}",
                            mqttCtx->rx_buf);
                        mqttCtx->stat = WMQ_PUB;
                        XMEMSET(&mqttCtx->publish, 0, sizeof(MqttPublish));
                        mqttCtx->publish.retain = 0;
                        mqttCtx->publish.qos = mqttCtx->qos;
                        mqttCtx->publish.duplicate = 0;
                        mqttCtx->publish.topic_name = AWSIOT_PUBLISH_TOPIC;
                        mqttCtx->publish.packet_id = mqtt_get_packetid();
                        mqttCtx->publish.buffer = (byte*)mqttCtx->app_ctx;
                        mqttCtx->publish.total_len = (word32)XSTRLEN((char*)mqttCtx->app_ctx);
                        rc = MqttClient_Publish(&mqttCtx->client, &mqttCtx->publish);
                        PRINTF("MQTT Publish: Topic %s, %s (%d)",
                            mqttCtx->publish.topic_name,
                            MqttClient_ReturnCodeToString(rc), rc);
                    }
                }
            #endif
                else if (rc == MQTT_CODE_ERROR_TIMEOUT) {
                    /* Keep Alive */
                    PRINTF("Keep-alive timeout, sending ping");

                    rc = MqttClient_Ping_ex(&mqttCtx->client, &mqttCtx->ping);
                    if (rc == MQTT_CODE_CONTINUE) {
                        return rc;
                    }
                    else if (rc != MQTT_CODE_SUCCESS) {
                        PRINTF("MQTT Ping Keep Alive Error: %s (%d)",
                            MqttClient_ReturnCodeToString(rc), rc);
                        break;
                    }
                }
                else if (rc != MQTT_CODE_SUCCESS) {
                    /* There was an error */
                    PRINTF("MQTT Message Wait: %s (%d)",
                        MqttClient_ReturnCodeToString(rc), rc);
                    break;
                }
            } while (1);

            /* Check for error */
            if (rc != MQTT_CODE_SUCCESS) {
                goto disconn;
            }
        }
        FALL_THROUGH;

        case WMQ_DISCONNECT:
        {
            /* Disconnect */
            rc = MqttClient_Disconnect(&mqttCtx->client);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }
            PRINTF("MQTT Disconnect: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                goto disconn;
            }
        }
        FALL_THROUGH;

        case WMQ_NET_DISCONNECT:
        {
            mqttCtx->stat = WMQ_NET_DISCONNECT;

            rc = MqttClient_NetDisconnect(&mqttCtx->client);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }
            PRINTF("MQTT Socket Disconnect: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
        }
        FALL_THROUGH;

        case WMQ_DONE:
        {
            mqttCtx->stat = WMQ_DONE;
            rc = mqttCtx->return_code;
            goto exit;
        }

        case WMQ_UNSUB: /* not used */
        case WMQ_PING:
        default:
            rc = MQTT_CODE_ERROR_STAT;
            goto exit;
    } /* switch */

disconn:
    mqttCtx->stat = WMQ_NET_DISCONNECT;
    mqttCtx->return_code = rc;
    rc = MQTT_CODE_CONTINUE;

exit:

    if (rc != MQTT_CODE_CONTINUE) {
        /* Free resources */
        if (mqttCtx->tx_buf) WOLFMQTT_FREE(mqttCtx->tx_buf);
        if (mqttCtx->rx_buf) WOLFMQTT_FREE(mqttCtx->rx_buf);

        /* Cleanup network */
        MqttClientNet_DeInit(&mqttCtx->net);

        MqttClient_DeInit(&mqttCtx->client);
    }

    return rc;
}
#endif /* ENABLE_AWSIOT_EXAMPLE */


/* so overall tests can pull in test function */
    #ifdef USE_WINDOWS_API
        #include <windows.h> /* for ctrl handler */

        static BOOL CtrlHandler(DWORD fdwCtrlType)
        {
            if (fdwCtrlType == CTRL_C_EVENT) {
            #ifdef ENABLE_AWSIOT_EXAMPLE
                mStopRead = 1;
            #endif
                PRINTF("Received Ctrl+c");
                return TRUE;
            }
            return FALSE;
        }
    #elif HAVE_SIGNAL
        #include <signal.h>
        static void sig_handler(int signo)
        {
            if (signo == SIGINT) {
            #ifdef ENABLE_AWSIOT_EXAMPLE
                mStopRead = 1;
            #endif
                PRINTF("Received SIGINT");
            }
        }
    #endif

#ifdef NO_MAIN_DRIVER
    int awsiot_main(int argc, char** argv)
#else
    int main(int argc, char** argv)
#endif /* NO_MAIN_DRIVER */
    {
        int rc;
    #ifdef ENABLE_AWSIOT_EXAMPLE
        MQTTCtx mqttCtx;
        char pubMsg[AWSIOT_PUBLISH_MSG_SZ] = {0};

        /* init defaults */
        mqtt_init_ctx(&mqttCtx);
        mqttCtx.app_name = "awsiot";
        mqttCtx.host = AWSIOT_HOST;
        mqttCtx.qos = AWSIOT_QOS;
        mqttCtx.keep_alive_sec = AWSIOT_KEEP_ALIVE_SEC;
        mqttCtx.client_id = AWSIOT_DEVICE_ID;
        mqttCtx.topic_name = AWSIOT_SUBSCRIBE_TOPIC;
        mqttCtx.cmd_timeout_ms = AWSIOT_CMD_TIMEOUT_MS;
        mqttCtx.use_tls = 1;
        mqttCtx.app_ctx = pubMsg;

        /* parse arguments */
        rc = mqtt_parse_args(&mqttCtx, argc, argv);
        if (rc != 0) {
            return rc;
        }
    #endif

    #ifdef USE_WINDOWS_API
        if (SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE) == FALSE) {
            PRINTF("Error setting Ctrl Handler! Error %d", (int)GetLastError());
        }
    #elif HAVE_SIGNAL
        if (signal(SIGINT, sig_handler) == SIG_ERR) {
            PRINTF("Can't catch SIGINT");
        }
    #endif

    #ifdef ENABLE_AWSIOT_EXAMPLE
        do {
            rc = awsiot_test(&mqttCtx);
        } while (rc == MQTT_CODE_CONTINUE);

        mqtt_free_ctx(&mqttCtx);
    #else
        (void)argc;
        (void)argv;

        /* This example requires wolfSSL 3.9.1 or later with base64encode enabled */
        PRINTF("Example not compiled in!");
        rc = 0; /* return success, so make check passes with TLS disabled */
    #endif

        return (rc == 0) ? 0 : EXIT_FAILURE;
    }
