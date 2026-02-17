from tinydb import TinyDB, Query
from aiohttp import web
import socketio


db = TinyDB('user_keys.json')
db.truncate()

def create_user_schema(username, ik, sik, spk, spk_sign):
    return {"username": username, "ik": ik, "sik": sik, "spk": spk, "spk_sign": spk_sign}


def find_user(username):
    query = Query()
    res = db.search(query.username == username)
    if len(res):
        return (True, res[0])
    else:
        return (False, None)


def update_user(username, user):
    query = Query()
    db.update(user, query.username == username)


def add_user(username, ik, sik, spk, spk_sign):
    user_json = create_user_schema(username, ik, sik, spk, spk_sign)
    if (find_user(username)[0]):
        update_user(username, user_json)
    else:
        db.insert(user_json)

def update_user_spk(username, spk, spk_sign):
    res = find_user(username)
    if (not res[0]):
        raise Exception(f"User {username} not found!")

    user = res[1]

    res['spk'] = spk
    res['spk_sign'] = spk_sign

    update_user(username, user)

def delete_user(username):
    query = Query()
    user_json = find_user(username)  # lista di record trovati

    if user_json[0]:  # se esiste almeno un utente con questo username
        db.remove(query.username == username)
        print(f"Utente '{username}' eliminato dal db.")
    else:
        print(f"Utente '{username}' non trovato, niente da eliminare.")



def request_prekey(username):
    res = find_user(username)
    if (not res[0]):
        raise Exception(f"User {username} not found!")

    user = res[1]

    return {"ik": user['ik'], "sik": user['sik'], "spk": user['spk'], "spk_sign": user['spk_sign']}

sio = socketio.AsyncServer(
    logger=True,
    engineio_logger=True,
    ping_timeout=5,
    ping_interval=5
)
app = web.Application()

sio.attach(app)

user_map = {}
sid_map = {}

@sio.event
def connect(sid, environ):
    print('connect ', sid)

@sio.on('pongi')
async def pongi(sid, data):
    await sio.emit("pingi", "sankalp")
    return True

@sio.on("register_user")
async def register_user(sid, data):
    username = data["username"]
    print("REGISTER USER: ", data, "username:", username)
    # 🔴 Controllo: username già in uso?
    if username in user_map:
        return {"ok": False, "error": "username_taken"}



    # salvale in TinyDB
    add_user(data["username"], data["ik"], data["sik"], data["spk"], data["spk_sig"])

    # registra l'utente: QUI ora salvi il sid, non "..."
    user_map[username] = sid
    sid_map[sid] = username

    users = list(user_map.keys())


    # notifica gli altri che è entrato
    await sio.emit("user_joined", {"username": username}, skip_sid=sid)

    return {"ok": True, "users": users}


async def _cleanup_user(username: str | None, sid: str | None):
    print(f"_cleanup_user: username={username}, sid={sid}")

    # Prova a recuperare username se manca ma hai sid
    if username is None and sid is not None:
        for u, s in user_map.items():
            if s == sid:
                username = u
                print("cleanup fallback: trovato username", username, "per sid", sid)
                break

    # Se ancora non hai username, non puoi pulire user_map, ma puoi loggare
    if username is None:
        print("cleanup: username ancora None, niente da rimuovere da user_map")
    else:
        if username in user_map:
            print("cleanup: rimuovo", username, "da user_map")
            del user_map[username]
        else:
            print("cleanup: username", username, "non era in user_map")

    if sid is not None:
        if sid in sid_map:
            print("cleanup: rimuovo", sid, "da sid_map")
            del sid_map[sid]
        else:
            print("cleanup: sid", sid, "non era in sid_map")

    if username is not None:
        await sio.emit("user_left", {"username": username}, skip_sid=sid)
    else:
        print("cleanup: nessun username da notificare in user_left")

@sio.on('request_users')
async def on_request_users(sid):
    return list(user_map.keys())

@sio.on('request_prekey')
async def on_request_prekey(sid, data):
    try:
        prekey_bundle = request_prekey(data["username"])
    except:
        return False, {}
    return True, prekey_bundle

@sio.on('x3dh_message')
async def on_x3dh_message(sid, data):
    if not data['username'] in user_map:
        return False
    
    res = await sio.call('x3dh_message', data, sid=user_map[data['username']])
    return res

# @sio.on("logout")
# async def on_logout(sid):
#     print("logout event for sid", sid)
#     delete_user(sid_map[sid])
#     print("Elimino l'utente dalla mappa e dall'sid")
#     username = sid_map.get(sid)
#     del user_map[sid_map[sid]]
#     del sid_map[sid]
#     await _cleanup_user(username, sid)
#     await sio.disconnect(sid)
#



@sio.event
async def disconnect(sid):
    print("disconnect event for sid", sid)
    print("sid_map at disconnect:", sid_map)
    username = sid_map.get(sid)
    print("disconnect username:", username)

    if username is not None:
        delete_user(username)   # TinyDB: chiavi
        print("Elimino l'utente dal DB")
    else:
        print("disconnect: nessun username trovato per sid", sid)

    await _cleanup_user(username, sid)

    delete_user(username)
    print("Elimino l'utente dal DB")
    await _cleanup_user(username, sid)

@sio.on('ratchet_msg')
async def on_ratchet_msg(sid, data):
    if not data['username'] in user_map:
        return False

    res = await sio.call('ratchet_msg', data, sid=user_map[data['username']])
    return res

@sio.on("get_users")
async def on_get_users(sid):
    # user_map: dict {username: ...}
    usernames = list(user_map.keys())
    return {"users": usernames}

if __name__ == '__main__':

    web.run_app(app)