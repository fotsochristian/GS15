from threading import Thread
import socket, pickle
from biblio import *


# Lists For Clients arguments
persons = []

# Server nickname
nickname = 'Server'

# Reception buffer size
BUFF_SIZE = 16384

# Diffie-Hellman Parameters
DH_PARAM = random.choice(LARGE_PRIMES)
DH_p = str(DH_PARAM[0])
DH_g = str(DH_PARAM[1])


class Person:
    cli = None
    ip = None
    nick = None
    pub_keys = None


class Keys:
    id_pub = None
    sigPK_pub = None
    sign_SigPK_pub = None
    eph_pub = None
    otPK_pub = None


def Send(client):
    pass
    '''while True:
        msg = input()
        data = wrap(msg)
        for person in persons:
            person.cli.send(data)'''


def Reception(client):
    while True:
        requete_client = client.recv(BUFF_SIZE)
        for person in persons:
            if person.cli != client:
                person.cli.send(requete_client)

        if not requete_client : #Si on pert la connexion
            print("CLOSE")
            break


Host = "127.0.0.1"
Port = 55555

#Création du socket
socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

socket.bind((Host, Port))
socket.listen()


#Connection client
while len(persons) < 2:
    #Accept connection
    client, ip = socket.accept()
    print("Le client d'ip",ip,"s'est connecté")
    nickname = client.recv(BUFF_SIZE).decode('utf-8')

    #Sending Diffie-Hellman Parameters
    client.send(DH_p.encode('utf-8'))
    client.send(DH_g.encode('utf-8'))

    #Creating class for client
    person = Person()
    person.cli = client
    person.ip = ip
    person.nick = nickname

    #Receiving keys from client
    keys_bundle = pickle.loads(client.recv(BUFF_SIZE))
    person.pub_keys = keys_bundle

    print(f'clés reçues de {person.nick}')

    persons.append(person)

    envoi = Thread(target=Send, args=[client])
    recep = Thread(target=Reception, args=[client])

    envoi.start()
    recep.start()


# Transmission des clés
if len(persons) == 2:
    persons[0].cli.send(pickle.dumps(persons[1].pub_keys))
    persons[1].cli.send(pickle.dumps(persons[0].pub_keys))


recep.join()

client.close()
socket.close()