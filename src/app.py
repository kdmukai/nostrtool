import json
import ssl
import time
from binascii import unhexlify
from flask import Flask, request, render_template
from nostr.delegation import Delegation
from nostr.event import Event, EventKind
from nostr.key import Bip39PrivateKey, PrivateKey, PublicKey
from nostr.relay_manager import RelayManager

from client import client_bp


app = Flask(__name__)
app.register_blueprint(client_bp, url_prefix="/client")

with open('.app_secret', 'r') as secret_file:
    app.secret_key = secret_file.readline()



@app.route("/")
def index():
    print(request.host)
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
    if data_type == "existing":
        if privkey_data.startswith("nsec"):
            pk = PrivateKey.from_nsec(privkey_data)
        else:
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



@app.route("/nip26/create", methods=['POST'])
def nip26_create_and_sign_delegation_token():
    delegator_pk = PrivateKey(unhexlify(request.form["delegator_pk_hex"]))
    kinds_list = request.form.get("kinds")
    kinds = [int(k) for k in request.form["kinds"].split(",")] if kinds_list else []
    valid_from = request.form["valid_from"]
    valid_until = request.form["valid_until"]

    delegatee_pk_input = request.form["delegatee_pk"]
    if delegatee_pk_input:
        if delegatee_pk_input.startswith("nsec"):
            delegatee_pk = PrivateKey.from_nsec(delegatee_pk_input)
        else:
            delegatee_pk = PrivateKey(unhexlify(delegatee_pk_input))
    else:
        delegatee_pk = PrivateKey()

    delegation = Delegation(
        delegator_pubkey=delegator_pk.public_key.hex(),
        delegatee_pubkey=delegatee_pk.public_key.hex(),
        event_kinds=kinds,
        valid_from=valid_from,
        valid_until=valid_until,
    )
    delegator_pk.sign_delegation(delegation)

    if delegation.event_kinds:
        kinds_descriptions = [f"{k}: {EventKind.ALL_KINDS[k]}" for k in delegation.event_kinds]
    else:
        kinds_descriptions = ["(ALL)"]

    return dict(
        delegation_token=delegation.delegation_token,
        delegator_npub=delegator_pk.public_key.bech32(),
        delegator_hex=delegator_pk.public_key.hex(),
        delegatee_npub=delegatee_pk.public_key.bech32(),
        delegatee_pubkey_hex=delegatee_pk.public_key.hex(),
        delegatee_nsec=delegatee_pk.bech32(),
        delegatee_privkey_hex=delegatee_pk.hex(),
        event_kinds="\n".join(kinds_descriptions),
        valid_from=delegation.valid_from,
        valid_until=delegation.valid_until,
        signature=delegation.signature,
        delegation_tag=str(delegation.get_tag()),
    )



@app.route("/nip26/sign", methods=['POST'])
def nip26_sign_delegation_token():
    delegator_pk = PrivateKey(unhexlify(request.form["delegator_pk_hex"]))
    delegation_token = request.form["delegation_token"]

    # Providing the delegatee PK is optional
    delegatee_pk = None
    delegatee_pk_input = request.form.get("delegatee_pk")
    if delegatee_pk_input:
        if delegatee_pk_input.startswith("nsec"):
            delegatee_pk = PrivateKey.from_nsec(delegatee_pk_input)
        else:
            delegatee_pk = PrivateKey(unhexlify(delegatee_pk_input))

    try:
        delegation = Delegation.from_token(delegator_pubkey=delegator_pk.public_key.hex(), delegation_token=delegation_token)
        delegatee_pubkey = PublicKey(unhexlify(delegation.delegatee_pubkey))
    except Exception as e:
        print(e)

    delegator_pk.sign_delegation(delegation)

    if delegation.event_kinds:
        kinds_descriptions = [f"{k}: {EventKind.ALL_KINDS[k]}" for k in delegation.event_kinds]
    else:
        kinds_descriptions = "(ALL)"

    return dict(
        delegator_npub=delegator_pk.public_key.bech32(),
        delegator_hex=delegator_pk.public_key.hex(),
        delegatee_npub=delegatee_pubkey.bech32(),
        delegatee_pubkey_hex=delegatee_pubkey.hex(),
        delegatee_nsec=delegatee_pk.bech32() if delegatee_pk else None,
        delegatee_privkey_hex=delegatee_pk.hex() if delegatee_pk else None,
        event_kinds="\n".join(kinds_descriptions),
        valid_from=delegation.valid_from,
        valid_until=delegation.valid_until,
        signature=delegation.signature,
        delegation_tag=str(delegation.get_tag()),
    )



@app.route("/event/kinds", methods=['GET'])
def get_event_kinds():
    """ Fetch the ID and description of all supported event kinds """
    return dict(kinds=[[k, v] for k, v in EventKind.ALL_KINDS.items()])



@app.route("/event/sign", methods=['POST'])
def event_sign():
    event = None
    pk = PrivateKey(unhexlify(request.form["pk_hex"]))
    data_type = request.form["type"]

    if data_type == "raw_json":
        event_json = request.form["event_data"]
        try:
            event = Event.from_json(event_json)
        except Exception as e:
            print(e)

    else:
        msg = request.form.get("event_data")
        tags = []

        if "metadata" in data_type:
            event_kind = EventKind.SET_METADATA
        elif "contacts" in data_type:
            event_kind = EventKind.CONTACTS
        else:
            event_kind = EventKind.TEXT_NOTE

        if "nip26" in data_type:
            # We're signing w/the delegatee's PK. Need to include their delegation tag.
            import ast
            delegation_tag = ast.literal_eval(request.form["delegation_tag"])
            tags=[delegation_tag]
        
        event = Event(content=msg, kind=event_kind, tags=tags)

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

        relay_manager = RelayManager()
        for relay in relays:
            relay_manager.add_relay(
                url=f"wss://{relay}",
            )
            print(f"added {relay}")

        time.sleep(1.5) # allow the connections to open

        print("Publishing!")
        relay_manager.publish_event(event)
        time.sleep(1) # allow the messages to send

        relay_manager.close_all_relay_connections()
        print("done")
    except Exception as e:
        import traceback
        traceback.print_exc()

    return dict(
        kind=event.kind,
        note_id=event.note_id
    )
