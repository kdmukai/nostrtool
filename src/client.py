"""
    Super-basic convenience client w/optional session-based PK + delegation tag storage
"""

from flask import request, session, render_template, Blueprint
from nostr.key import PrivateKey, PublicKey



client_bp = Blueprint("client", __name__, template_folder='templates/client')



@client_bp.route("/")
@client_bp.route("/note")
def note():
    return render_template("note.html")



@client_bp.route("/nip_26_note")
def nip26_note():
    return render_template("nip26_note.html")



@client_bp.route("/user", methods=['GET', 'POST'])
def user():
    if request.method == "POST":
        if "clear" in request.form:
            session.clear()

        else:
            session.clear()
            for k, v in request.form.items():
                if v:
                    session[k] = v
            
            if "delegator_nsec" in session:
                pk = PrivateKey.from_nsec(session["delegator_nsec"])
                session["pk_hex"] = pk.hex()
            
            session["delegator_pubkey_hex"] = PublicKey.from_npub(session["delegator_npub"]).hex()
            
            if "nip26_delegatee_privkey_hex" in session:
                pk = PrivateKey(bytes.fromhex(session["nip26_delegatee_privkey_hex"]))
                session["nip26_delegatee_nsec"] = pk.bech32()
                session["nip26_delegatee_npub"] = pk.public_key.bech32()
                session["nip26_delegatee_pubkey_hex"] = pk.public_key.hex()

    return render_template("user.html")



@client_bp.route("/metadata")
def metadata():
    return render_template("metadata.html")



@client_bp.route("/nip26_metadata")
def nip26_metadata():
    return render_template("nip26_metadata.html")


@client_bp.route("/contacts")
def contacts():
    return render_template("contacts.html")

