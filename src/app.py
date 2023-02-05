import json
import ssl
import time
from binascii import unhexlify
from flask import Flask, request, render_template
from nostr.delegation import Delegation
from nostr.event import Event
from nostr.key import Bip39PrivateKey, PrivateKey, PublicKey
from nostr.relay_manager import RelayManager


app = Flask(__name__)



@app.route("/")
def hello_world():
    return render_template("index.html")



@app.route("/key/create", methods=['POST'])
def create_pk():
    mnemonic = None
    type = request.form["type"]
    if type == "raw":
        pk = PrivateKey()
    else:
        pk = Bip39PrivateKey.with_mnemonic_length(int(request.form["mnemonic_length"]))
        mnemonic = ", ".join(pk.mnemonic)

    return dict(
        pk_hex=pk.hex(),
        pk_nsec=pk.bech32(),
        pubkey_hex=pk.public_key.hex(),
        pubkey_npub=pk.public_key.bech32(),
        mnemonic=mnemonic
    )



@app.route("/key/load", methods=['POST'])
def load_pk():
    data_type = request.form["type"]
    privkey_data = request.form["privkey_data"]
    if data_type == "nsec":
        pk = PrivateKey.from_nsec(privkey_data)
    elif data_type == "hex":
        pk = PrivateKey(unhexlify(privkey_data))
    else:
        if "," in privkey_data:
            mnemonic = privkey_data.split(",")
        else:
            mnemonic = privkey_data.split()
        pk = Bip39PrivateKey(mnemonic=mnemonic)

    return dict(
        pk_hex=pk.hex(),
        pk_nsec=pk.bech32(),
        pubkey_hex=pk.public_key.hex(),
        pubkey_npub=pk.public_key.bech32(),
    )



@app.route("/nip26/sign", methods=['POST'])
def nip26_sign_delegation_token():
    pk = None
    pk = PrivateKey(unhexlify(request.form["pk_hex"]))
    delegation_token = request.form["delegation_token"]
    try:
        delegation = Delegation.from_token(delegator_pubkey=pk.public_key.hex(), delegation_token=delegation_token)
        delegatee_pubkey = PublicKey(unhexlify(delegation.delegatee_pubkey))
    except Exception as e:
        print(e)

    pk.sign_delegation(delegation)

    return dict(
        delegator_npub=pk.public_key.bech32(),
        delegator_hex=pk.public_key.hex(),
        delegatee_npub=delegatee_pubkey.bech32(),
        delegatee_hex=delegatee_pubkey.hex(),
        event_kinds=delegation.event_kinds,
        valid_from=delegation.valid_from,
        valid_until=delegation.valid_until,
        signature=delegation.signature,
        delegation_tag=delegation.get_tag(),
    )



@app.route("/event/sign", methods=['POST'])
def event_sign_raw_json():
    pk = None
    event = None
    pk = PrivateKey(unhexlify(request.form["pk_hex"]))
    data_type = request.form["type"]

    if data_type == "text_note":
        msg = request.form["event_data"]
        event = Event(msg)

    elif data_type == "raw_json":
        event_json = request.form["event_data"]
        try:
            event = Event.from_json(event_json)
        except Exception as e:
            print(e)

    pk.sign_event(event)

    return dict(
        signature=event.signature,
        event_json=json.dumps(event.to_json(), indent=2),
        note_id=event.note_id,
    )




@app.route("/event/publish", methods=['POST'])
def event_publish():
    event_json = request.form["event_json"]
    relays = request.form["relays"].split()

    try:
        event = Event.from_json(event_json)

        relay_manager = RelayManager(ssl_options={"cert_reqs": ssl.CERT_NONE})
        for relay in relays:
            relay_manager.add_relay(f"wss://{relay}")
            print(f"added {relay}")
        relay_manager.open_connections() # NOTE: This disables ssl certificate verification
        time.sleep(1.25) # allow the connections to open

        print("Publishing!")
        relay_manager.publish_event(event)
        time.sleep(1) # allow the messages to send

        relay_manager.close_connections()
        print("done")
    except Exception as e:
        print(e)

    return dict(
        kind=event.kind,
        note_id=event.note_id
    )
