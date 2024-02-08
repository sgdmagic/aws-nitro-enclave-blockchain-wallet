#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import base64
import json
import logging
import os
import ssl
from http import client

import boto3

ssl_context = ssl.SSLContext()
ssl_context.verify_mode = ssl.CERT_NONE


LOG_LEVEL = os.getenv("LOG_LEVEL", "WARNING")
LOG_FORMAT = "%(levelname)s:%(lineno)s:%(message)s"
handler = logging.StreamHandler()

_logger = logging.getLogger("tx_manager_controller")
_logger.setLevel(LOG_LEVEL)
_logger.addHandler(handler)
_logger.propagate = False

client_kms = boto3.client("kms")

# We can define the name of the lambda as something like /call_enclave for clarity
# The input payload is freeform, allowing the enclave to scale for more use-cases easily
# The enclave instances are stateless, so we can scale them up and down as needed, beind a load balancer
def lambda_handler(event, context):
    """
    example requests
    
    # For wallet_generation
    
    {
    
    "enclave_payload": {
        "method_type": "wallet_generation",
        "user_data_list": [
            {"user_id": "user_id_1", "email": "email1@example.com", "kms_id": "KMSID1"},
            {"user_id": "user_id_2", "email": "email2@example.com", "kms_id": "KMSID2"},
            {"user_id": "user_id_3", "email": "email3@example.com", "kms_id": "KMSID3"}
        ]
        }
    }
    
    # For sign_transaction

    {
        "enclave_payload": {
            "method_type": "sign_transaction",
            "encrypted_private_key": "PK123",
            ""encrypted_data_key": "0xblahblah",
            "kms_id": "KMSID1",
            "transaction_payload": {
                "value": 0.01,
                "to": "0xa5D3241A1591061F2a4bB69CA0215F66520E67cf",
                "nonce": 0,
                "type": 2,
                "chainId": 4,
                "gas": 100000,
                "maxFeePerGas": 100000000000,
                "maxPriorityFeePerGas": 3000000000
            }
        }
    }

    """
    nitro_instance_private_dns = os.getenv("NITRO_INSTANCE_PRIVATE_DNS")

    if not nitro_instance_private_dns:
        _logger.fatal(
            "NITRO_INSTANCE_PRIVATE_DNS environment variable need to be set"
        )
        
    # wallet_generation lambda
    enclave_payload = event.get("enclave_payload")

    if not enclave_payload:
        raise Exception(
            "enclave_payload is a required input for enclave operations"
        )

    https_nitro_client = client.HTTPSConnection(
        "{}:{}".format(nitro_instance_private_dns, 443), context=ssl_context
    )

    try:
        https_nitro_client.request(
            "POST",
            "/",
            body=json.dumps(
                {"enclave_payload": enclave_payload}
            ),
        )
        response = https_nitro_client.getresponse()
    except Exception as e:
        raise Exception(
            "exception happened sending decryption request to Nitro Enclave: {}".format(
                e
            )
        )

    _logger.debug("response: {} {}".format(response.status, response.reason))

    response_raw = response.read()

    _logger.debug("response data: {}".format(response_raw))
    response_parsed = json.loads(response_raw)

    return response_parsed
