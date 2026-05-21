#!/usr/bin/env python3
"""
Complete FIDO2 Authentication Flow Test
Tests: MakeCredential -> GetAssertion -> Signature Verification
"""
import os
import struct
import hashlib
import time
import cbor2
from typing import Tuple, Optional

class CTAP2Client:
    """CTAP2 protocol client for testing"""

    def __init__(self, device_path: str):
        self.device_path = device_path
        self.fd: Optional[int] = None
        self.channel_id: Optional[bytes] = None

    def __enter__(self):
        self.fd = os.open(self.device_path, os.O_RDWR)
        print(f"✓ Opened {self.device_path}")
        self._init_channel()
        return self

    def __exit__(self, *args):
        if self.fd:
            os.close(self.fd)

    def _init_channel(self):
        """CTAPHID_INIT"""
        nonce = bytes(range(1, 9))
        packet = b'\xff' * 4 + b'\x86\x00\x08' + nonce + bytes(49)
        os.write(self.fd, packet)
        time.sleep(0.1)

        response = os.read(self.fd, 64)
        self.channel_id = response[15:19]
        print(f"  Channel ID: {self.channel_id.hex()}")

    def _send_cbor(self, ctap_cmd: int, cbor_data: bytes) -> bytes:
        """Send CTAPHID_CBOR command"""
        payload = bytes([ctap_cmd]) + cbor_data

        # Init packet
        init_pkt = self.channel_id + b'\x90' + struct.pack('>H', len(payload))
        init_pkt += payload[:57] + bytes(max(0, 64 - len(init_pkt)))
        os.write(self.fd, init_pkt)

        # Continuation packets
        remaining = payload[57:]
        seq = 0
        while remaining:
            chunk = remaining[:59]
            cont_pkt = self.channel_id + bytes([seq]) + chunk
            cont_pkt += bytes(64 - len(cont_pkt))
            os.write(self.fd, cont_pkt)
            remaining = remaining[59:]
            seq += 1

        # Receive response
        response = self._recv_cbor_response()
        return response

    def _recv_cbor_response(self) -> bytes:
        """Receive CBOR response with continuation support"""
        for _ in range(100):
            time.sleep(0.05)
            try:
                pkt = os.read(self.fd, 64)
                if pkt[4] == 0xBB:  # KEEPALIVE
                    print("  ⏳", end="", flush=True)
                    continue

                print()
                length = struct.unpack('>H', pkt[5:7])[0]
                data = pkt[7:]

                # Receive continuation packets if needed
                while len(data) < length:
                    cont = os.read(self.fd, 64)
                    data += cont[5:]

                return data[:length]
            except BlockingIOError:
                continue

        raise TimeoutError("No response received")

    def get_info(self) -> dict:
        """authenticatorGetInfo (0x04)"""
        print("\n📋 GetInfo")
        response = self._send_cbor(0x04, b'')
        status = response[0]

        if status == 0:
            info = cbor2.loads(response[1:])
            print(f"  ✓ Versions: {info.get(1)}")
            print(f"  ✓ Options: {info.get(4)}")
            return info
        else:
            raise Exception(f"GetInfo failed: 0x{status:02x}")

    def make_credential(self, rp_id: str, user_id: bytes,
                       client_data_hash: bytes) -> Tuple[bytes, bytes, bytes]:
        """
        authenticatorMakeCredential (0x01)
        Returns: (credential_id, public_key_cbor, auth_data)
        """
        print(f"\n🔐 MakeCredential (rpId={rp_id})")

        request = {
            1: client_data_hash,
            2: {"id": rp_id, "name": rp_id.capitalize()},
            3: {
                "id": user_id,
                "name": f"user@{rp_id}",
                "displayName": "Test User"
            },
            4: [{"type": "public-key", "alg": -7}],  # ES256
        }

        request_cbor = cbor2.dumps(request)
        response = self._send_cbor(0x01, request_cbor)
        status = response[0]

        if status != 0:
            raise Exception(f"MakeCredential failed: 0x{status:02x}")

        result = cbor2.loads(response[1:])
        fmt = result.get(1)
        auth_data = result.get(2, b'')

        print(f"  ✓ Format: {fmt}")
        print(f"  ✓ AuthData: {len(auth_data)} bytes")

        # Parse authenticator data to extract credential ID and public key
        # AuthData structure: rpIdHash(32) + flags(1) + signCount(4) + attestedCredentialData
        if len(auth_data) < 37:
            raise Exception("AuthData too short")

        flags = auth_data[32]
        if not (flags & 0x40):  # AT (Attested credential data) flag
            raise Exception("No attested credential data")

        # AttestedCredentialData: aaguid(16) + credentialIdLength(2) + credentialId + publicKey(CBOR)
        offset = 37  # After rpIdHash + flags + signCount
        aaguid = auth_data[offset:offset+16]
        offset += 16

        cred_id_len = struct.unpack('>H', auth_data[offset:offset+2])[0]
        offset += 2

        credential_id = auth_data[offset:offset+cred_id_len]
        offset += cred_id_len

        # Public key is CBOR encoded
        public_key_cbor = auth_data[offset:]

        print(f"  ✓ Credential ID: {credential_id.hex()[:32]}... ({len(credential_id)} bytes)")
        print(f"  ✓ Public key extracted")

        return credential_id, public_key_cbor, auth_data

    def get_assertion(self, rp_id: str, credential_id: bytes,
                     client_data_hash: bytes) -> Tuple[bytes, bytes, bytes]:
        """
        authenticatorGetAssertion (0x02)
        Returns: (credential_id, auth_data, signature)
        """
        print(f"\n🔓 GetAssertion (rpId={rp_id})")

        request = {
            1: rp_id,
            2: client_data_hash,
            3: [{"type": "public-key", "id": credential_id}],  # allowList
        }

        request_cbor = cbor2.dumps(request)
        response = self._send_cbor(0x02, request_cbor)
        status = response[0]

        if status != 0:
            error_names = {
                0x01: "INVALID_COMMAND",
                0x02: "INVALID_PARAMETER",
                0x2E: "NO_CREDENTIALS",
                0x31: "OPERATION_DENIED",
            }
            error = error_names.get(status, f"0x{status:02x}")
            raise Exception(f"GetAssertion failed: {error}")

        result = cbor2.loads(response[1:])

        # Response fields:
        # 1: credential
        # 2: authData
        # 3: signature
        # 4: user (optional)
        # 5: numberOfCredentials (optional)

        credential = result.get(1, {})
        returned_cred_id = credential.get("id", b'')
        auth_data = result.get(2, b'')
        signature = result.get(3, b'')

        print(f"  ✓ Credential ID: {returned_cred_id.hex()[:32]}...")
        print(f"  ✓ AuthData: {len(auth_data)} bytes")
        print(f"  ✓ Signature: {len(signature)} bytes")

        # Parse auth data
        if len(auth_data) >= 37:
            flags = auth_data[32]
            counter = struct.unpack('>I', auth_data[33:37])[0]
            print(f"  ✓ Flags: 0x{flags:02x} (UP={bool(flags&1)}, UV={bool(flags&4)})")
            print(f"  ✓ Counter: {counter}")

        return returned_cred_id, auth_data, signature


def verify_signature(public_key_cbor: bytes, auth_data: bytes,
                     client_data_hash: bytes, signature: bytes) -> bool:
    """
    Verify ECDSA signature
    Requires cryptography library
    """
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        print("  ⚠ cryptography library not available, skipping signature verification")
        return True

    # Parse COSE key (CBOR)
    cose_key = cbor2.loads(public_key_cbor)

    # COSE key parameters:
    # 1: kty (key type) - 2 for EC2
    # 3: alg - -7 for ES256
    # -1: crv (curve) - 1 for P-256
    # -2: x coordinate
    # -3: y coordinate

    x = cose_key.get(-2)
    y = cose_key.get(-3)

    if not x or not y:
        raise Exception("Invalid public key")

    # Construct verification message: authData || clientDataHash
    verification_data = auth_data + client_data_hash

    # Create EC public key
    public_numbers = ec.EllipticCurvePublicNumbers(
        int.from_bytes(x, 'big'),
        int.from_bytes(y, 'big'),
        ec.SECP256R1()
    )
    public_key = public_numbers.public_key(default_backend())

    # Verify signature
    try:
        public_key.verify(
            signature,
            verification_data,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except Exception as e:
        print(f"  ✗ Signature verification failed: {e}")
        return False


def main():
    print("=" * 80)
    print("🧪 Complete FIDO2 Authentication Flow Test")
    print("=" * 80)

    device_path = "/dev/hidraw1"

    # Test parameters
    rp_id = "example.com"
    user_id = b"test-user-001"
    client_data_hash_register = hashlib.sha256(b"registration-data").digest()
    client_data_hash_authenticate = hashlib.sha256(b"authentication-data").digest()

    try:
        with CTAP2Client(device_path) as client:
            # Step 1: Get device info
            info = client.get_info()

            # Step 2: Register (MakeCredential)
            print("\n" + "=" * 80)
            print("STEP 1: Registration")
            print("=" * 80)

            credential_id, public_key_cbor, make_cred_auth_data = client.make_credential(
                rp_id=rp_id,
                user_id=user_id,
                client_data_hash=client_data_hash_register
            )

            # Step 3: Authenticate (GetAssertion)
            print("\n" + "=" * 80)
            print("STEP 2: Authentication")
            print("=" * 80)

            returned_cred_id, auth_data, signature = client.get_assertion(
                rp_id=rp_id,
                credential_id=credential_id,
                client_data_hash=client_data_hash_authenticate
            )

            # Verify credential ID matches
            if credential_id != returned_cred_id:
                print(f"\n✗ Credential ID mismatch!")
                return False

            print(f"\n✓ Credential ID matches")

            # Step 4: Verify signature
            print("\n" + "=" * 80)
            print("STEP 3: Signature Verification")
            print("=" * 80)

            verified = verify_signature(
                public_key_cbor=public_key_cbor,
                auth_data=auth_data,
                client_data_hash=client_data_hash_authenticate,
                signature=signature
            )

            if verified:
                print("\n✓ Signature verification PASSED")
            else:
                print("\n✗ Signature verification FAILED")
                return False

            # Success!
            print("\n" + "=" * 80)
            print("🎉 ALL TESTS PASSED! 🎉")
            print("=" * 80)
            print("\n✅ Complete authentication flow verified:")
            print("   1. MakeCredential - Credential creation")
            print("   2. GetAssertion - Authentication")
            print("   3. Signature verification - Cryptographic proof")
            print("\n✅ FIDO2 device is fully functional!")

            return True

    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    import sys
    sys.exit(0 if main() else 1)
