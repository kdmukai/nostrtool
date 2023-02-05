var pk_slide_open = null;

function clearPKDisplayFields() {
    document.getElementById("pk_nsec").value = "";
    document.getElementById("pk_hex").value = "";
    document.getElementById("pubkey_npub").value = "";
    document.getElementById("pubkey_hex").value = "";
}

function createNewPK(keytype) {
    let target = null;
    let data = new FormData();
    data.append("type", keytype);

    clearPKDisplayFields();

    if (keytype == "bip39_12") {
        data.append("mnemonic_length", 12);
        target = document.getElementById("bip39_mnemonic_container")
    } else if (keytype == "bip39_24") {
        target = data.append("mnemonic_length", 24);
        target = document.getElementById("bip39_mnemonic_container")
    }

    // Close an open option, if any
    if ((pk_slide_open !== null && target === null) || (pk_slide_open !== null && target !== null && pk_slide_open.id != target.id)) {
        slideUp(pk_slide_open);
        pk_slide_open = null;
    }
    
    if (target !== null && pk_slide_open === null) {
        slideDown(target);
        pk_slide_open = target;
    }

    fetch(
        "/key/create",
        {
            method: 'POST',
            body: data
        }
    )
    .then(response => response.json())
    .then(result => {
        if (keytype.startsWith("bip39")) {
            document.getElementById("bip39_mnemonic").value = result.mnemonic;
        } else {
            document.getElementById("bip39_mnemonic").value = "";
        }
        document.getElementById("pk_nsec").value = result.pk_nsec;
        document.getElementById("pk_hex").value = result.pk_hex;
        document.getElementById("pubkey_npub").value = result.pubkey_npub;
        document.getElementById("pubkey_hex").value = result.pubkey_hex;
    })
}



function prepareLoadPK(keytype) {
    clearPKDisplayFields();

    if (keytype == "nsec") {
        target = document.getElementById("input_nsec_container");
    } else if (keytype == "hex") {
        target = document.getElementById("input_hex_container");
    } else if (keytype == "bip39") {
        target = document.getElementById("input_mnemonic_container");
    }

    // Close an open option, if any
    if (pk_slide_open !== null && pk_slide_open.id != target.id) {
        slideUp(pk_slide_open);
        pk_slide_open = null;
    }
    
    if (pk_slide_open === null) {
        slideDown(target);
        pk_slide_open = target;
    }

}



function loadPK(keytype, targetId) {
    let target = document.getElementById(targetId);

    let data = new FormData();
    data.append("type", keytype);
    data.append("privkey_data", target.value)

    fetch(
        "/key/load",
        {
            method: 'POST',
            body: data
        }
    )
    .then(response => response.json())
    .then(result => {
        document.getElementById("pk_nsec").value = result.pk_nsec;
        document.getElementById("pk_hex").value = result.pk_hex;
        document.getElementById("pubkey_npub").value = result.pubkey_npub;
        document.getElementById("pubkey_hex").value = result.pubkey_hex;
    })

}


var curNip26Slide = null;
function prepareLoadNip26(container_id) {
    if (curNip26Slide !== null && curNip26Slide.id != container_id) {
        slideUp(curNip26Slide);
        curNip26Slide = null;
    }

    target = document.getElementById(container_id);
    if(curNip26Slide === null) {
        slideDown(target);
        curNip26Slide = target;
    }
}



function nip26Sign(dataSource) {
    let data = new FormData();
    let delegation_token = document.getElementById(dataSource).value;
    data.append("delegation_token", delegation_token);
    data.append("pk_hex", document.getElementById("pk_hex").value);

    fetch(
        "/nip26/sign",
        {
            method: 'POST',
            body: data
        }
    )
    .then(response => response.json())
    .then(result => {
        document.getElementById("nip26_token").value = delegation_token;
        document.getElementById("nip26_delegator_npub").value = result.delegator_npub;
        document.getElementById("nip26_delegator_hex").value = result.delegator_hex;
        document.getElementById("nip26_delegatee_npub").value = result.delegatee_npub;
        document.getElementById("nip26_delegatee_hex").value = result.delegatee_hex;
        document.getElementById("nip26_kinds").value = result.event_kinds;
        document.getElementById("nip26_valid_from").value = new Date(result.valid_from * 1000).toISOString();
        document.getElementById("nip26_valid_until").value = new Date(result.valid_until * 1000).toISOString();
        document.getElementById("nip26_tag").value = result.delegation_tag;
        document.getElementById("nip26_signature").value = result.signature;
    })
}




/***************************************************************
 *      EVENTS
 ***************************************************************/
var curEventSlide = null;
function showEvent(container_id) {
    if (curEventSlide !== null && curEventSlide.id != container_id) {
        slideUp(curEventSlide);
        curEventSlide = null;
    }

    target = document.getElementById(container_id);
    if(curEventSlide === null) {
        slideDown(target);
        curEventSlide = target;
    }
}


function eventSign(type, dataSource) {
    let data = new FormData();
    data.append("type", type);
    data.append("event_data", document.getElementById(dataSource).value);
    data.append("pk_hex", document.getElementById("pk_hex").value);

    fetch(
        "/event/sign",
        {
            method: 'POST',
            body: data
        }
    )
    .then(response => response.json())
    .then(result => {
        document.getElementById("event_json").value = result.event_json;
        document.getElementById("event_note_id").value = result.note_id;
        document.getElementById("event_signature").value = result.signature;
    })
}



function eventPublish() {
    let data = new FormData();
    data.append("event_json", document.getElementById("event_json").value);
    data.append("relays", document.getElementById("relays_list").value);

    showLoader();
    fetch(
        "/event/publish",
        {
            method: 'POST',
            body: data
        }
    )
    .then(response => response.json())
    .then(result => {
        console.log("Done!");
    })
    .finally(() => {
        hideLoader();
    })
}



document.addEventListener("DOMContentLoaded", function(){
    let slideBtnClick = (id) => {
        let target = document.getElementById(id);
        target.addEventListener('click', () => slideToggle(target.parentElement.querySelector(".section_content")));
    }

    slideBtnClick("header_event");
    slideBtnClick("header_nip26");
    slideBtnClick("header_relays");
    slideBtnClick("header_tips");
});



/**
 * see: https://codepen.io/ivanwebstudio/pen/OJVzPBL
 */
var speedAnimation = 400;

function slideUp(target, duration=speedAnimation) {
    target.style.transitionProperty = 'height, margin, padding';
    target.style.transitionDuration = duration + 'ms';
    target.style.boxSizing = 'border-box';
    target.style.height = target.offsetHeight + 'px';
    target.offsetHeight;
    target.style.overflow = 'hidden';
    target.style.height = 0;
    target.style.paddingTop = 0;
    target.style.paddingBottom = 0;
    target.style.marginTop = 0;
    target.style.marginBottom = 0;
    window.setTimeout( () => {
      target.style.display = 'none';
      target.style.removeProperty('height');
      target.style.removeProperty('padding-top');
      target.style.removeProperty('padding-bottom');
      target.style.removeProperty('margin-top');
      target.style.removeProperty('margin-bottom');
      target.style.removeProperty('overflow');
      target.style.removeProperty('transition-duration');
      target.style.removeProperty('transition-property');
      //alert("!");
    }, duration);
}

function slideDown(target, duration=speedAnimation) {
    target.style.removeProperty('display');
    let display = window.getComputedStyle(target).display;

    if (display === 'none')
      display = 'block';

    target.style.display = display;
    let height = target.offsetHeight;
    target.style.overflow = 'hidden';
    target.style.height = 0;
    target.style.paddingTop = 0;
    target.style.paddingBottom = 0;
    target.style.marginTop = 0;
    target.style.marginBottom = 0;
    target.offsetHeight;
    target.style.boxSizing = 'border-box';
    target.style.transitionProperty = "height, margin, padding";
    target.style.transitionDuration = duration + 'ms';
    target.style.height = height + 'px';
    target.style.removeProperty('padding-top');
    target.style.removeProperty('padding-bottom');
    target.style.removeProperty('margin-top');
    target.style.removeProperty('margin-bottom');
    window.setTimeout( () => {
      target.style.removeProperty('height');
      target.style.removeProperty('overflow');
      target.style.removeProperty('transition-duration');
      target.style.removeProperty('transition-property');
    }, duration);
}

function slideToggle(target, duration=speedAnimation) {
    if (window.getComputedStyle(target).display === 'none') {
      return slideDown(target, duration);
    } else {
      return slideUp(target, duration);
    }
}


function showLoader() {
    document.getElementById("loader_grayout").style.display = "block";
    document.getElementById("loader").style.display = "block";
}

function hideLoader() {
    document.getElementById("loader_grayout").style.display = "none";
    document.getElementById("loader").style.display = "none";
}