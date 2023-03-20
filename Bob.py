from threading import Thread
import socket, pickle
from biblio import *


# Reception buffer size
BUFF_SIZE = 16384


class Message:
    ciph = None
    clair = None
    key = None
    sender = None
    count = None
    sign = None
    hmac = None
    ack = False


def wrap(msg, sender, count, key):
   message = Message()
   message.ciph = encrypt(msg, key)
   message.key = key
   message.sender = sender
   message.count = count
   message.sign = sign_rsa(message.ciph[0], ID_priv)
   message.hmac = hash512(message.ciph[0] + key)
   data = pickle.dumps(message)
   return data


def unwrap(data):
    message = pickle.loads(data)
    # Décodage du message
    message.clair = decrypt(message.ciph[1], message.key)
    return message


def Send(socket):
    # Initialisation du counter de messages
    counter = 0
    # Initialisation de la clé chainée
    chain_key = kdf(SK, random.random())[0]
    while True:
        msg = input()
        sender = nickname
        counter = counter + 1
        # Dérivation des Ratchet keys
        key = kdf(chain_key, msg)
        message_key = hash512(key[0])
        chain_key = hash512(key[1])
        data = wrap(msg, sender, counter, message_key)
        try:
            if msg == 'EXIT':
                socket.close()
                break
            else:
                socket.send(data)
        except:
            # Close Connection When Error
            print("An error occured!")
            socket.close()
            break


def Reception(socket):
    while True:
        requete_server = socket.recv(BUFF_SIZE)
        message_server = unwrap(requete_server)
        assert verif_rsa(message_server.ciph[0], message_server.sign, alice_pub_keys.id_pub)
        assert message_server.hmac == hash512(message_server.ciph[0] + message_server.key)
        # Acquittement de reception du massage
        assert not message_server.ack
        # Afffichage du message en clair
        print(f"{message_server.sender}: {message_server.clair}")


#username
nickname = input("Choose your nickname: ")
#mdp = input("Choose your password: ")

Host = "127.0.0.1"
Port = 55555

#Création du socket
socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect((Host, Port))

#Send nickname to server
nick = nickname.encode('utf-8')
socket.send(nick)

#Receive Diffie-Hellman Parameters from server
DH_p = int(socket.recv(BUFF_SIZE).decode('utf-8'))
DH_g = int(socket.recv(BUFF_SIZE).decode('utf-8'))

#Initialisation des clés
ID = rsa_key_gen()
ID_priv = ID[1]
ID_pub = ID[0]


SigPK = random.choice(LARGE_PRIMES)[0]
SigPK_pub = expo(DH_g, SigPK, DH_p)

Sign_SigPK_pub = sign_rsa(SigPK_pub, ID_priv)

Eph = random.choice(LARGE_PRIMES)[0]
Eph_pub = expo(DH_g, Eph, DH_p)

OtPK = [
[24521887092771159166045715300347305249547106742219861861377991398825129535373424915968039287110274164919209602073457856286937901029860793975828343059944238394066142718589001871791086694918954980738224908672116040981071720213070374912235580696399212617785549100438143589078445016559574124352620349096374383492562983175318508457386831584588498027226107607851598767672121057103331205210726879134478168951900486592560941944288319218071090053510833578179078793954495525866387030528679141915009708763990760184039438824740512008648507005748611812185789697152517870985361708959570621678594254081991209882775395847405767586801, 3],
[22839444407383592067477228598237087894821711338740598230213982959924700369030500783460260075094822456932227938262256194066016899464334223838383698842343850077804174514329371136649505051447086336576637904055930239050225730704876326020077865154636037555167571316819138605678832042590624439819311485941936212539555870175384705018276927907880772707626996266450130458935822318173179207466189697176858478886694388210739016372393749235142316346717114983586140991183290537106064849768295952177593897748608868983609966860381488988191679852402350272013529089370675116128531787719344032708255258596439974477667598621279325278591, 3],
[22272725703070295978744952677230349863153269992208800325273390486972039853351796073653680151765164600422856967018096718847862732764887218922120379639605123474380843013568881352112526504868121850081583362806828544133484924486493824130887482422970159914126272865815634706854713064807511255890766665320700455353936101915498622185756873913735216673831206173176643570816737036647073650480075911614011578032976420028959290884114073399158167099488286222343676495399025460694942127000103565718904864457429101804768310138369384230654406018744951506727106700404049922067471242969766467593242076578992020237226780320945651284403, 2],
[26176176093544562269786504101964642760782309724825298930979015650705396604588470780158283080499589291893616842350635686437330801398408056599251847963404486203120194998178899818209952062014061864780584370731742351340746504879476135134701347719065881419521418096194764734501038853645190907898010317041007783493033041307326056324565060410483526033313255693206280243380723876060048685514778713313097363396849793215569021359872780571459838393025029820508117229594049971286566036214430433931270581326369271718870566170650561603361968849816377966579772117285689864554353243644342302639814862449163442941278516978423163213957, 2],
[24812937955450887850798980047260912445445446074892966665500643301355704188246234097891926241412878593623479759839832134907732572747482337791582372902360147949309447158833135959859692083986363771248234136546124205836920950893788104572387950175926325571548463937165558638966443836077271665728503993082012651965544584327864955090506391196319650311362451614825024007431933842306467764881770167955179688063924162113194031229295652235342736003690199240525928516926393142877315999517196309108074021039783503993836836465094921077481248711463099533249710226967044495134072617499269592834220064040485957864352234399692976615221, 2],
[23882057305307002491789426393276932712898549590604917568446928335800079450781568193063376346432353899546404134075888701953304439300598246492062205289865963036746364526343401305436850744392914512087021995845199211881666082018444777328628124650017294272408418954344466257300234352099543717464928904068873651893984474328825535562422708835014823782298247295496466583901511774007265449252519873915163189418492165627421015995726418164160417817451631800438948419034949108073975999272903648821771931953435706884548441732787815393231209428276398016857535811785576781497931309097357240631054033161354091781505932945047882578647, 5],
[19755408162138789826990868035177138783076629861955018969770617320831913022426483496868289803744799348936764037953026369182485187809604566053824856621469420631569175818990833078413843824698746876368463646320310836381794860051500321085750080164220901247144818401285033256855239905373982009082278110580010664708590583512178210133834928123585530577946647786794542074839130484920038068382987854309736540966741387132644129141911395078738702027467093712228352265348328551475233446916593741258430964247744922975763495852854017946463667699600131773880092947542882825072747363310882498552493886165824290810401234535622491443039, 7],
[19062583724557570731379758460321755179886637765747224610913351111536063350073968183555802792146904892905998776283820467027575000852461632534587969460597901647243562832129316964807015456046554085759074168828272893905466780865918519956607055384287383794750343242034330612024579521083521564576956992870559468931448539359039305100568628214035910682030921558953782107933194188731990148847297916143489741987507559123226553751301331078758270505184679646763758097066435371403315828277309563495468584611604099298067233120437457959954866856385990545134178542524910130594221900829002346833909894525934560069601575159453655682219, 2],
[25987333277789289674466175814479518190497629938710495515338559738223437893483707883013262820333297925438999937950304470289128207266917510184356613160062975882757635041032042902189128566304678109845332915909636659315567663967464758944035699147336284298250873069910272033765708402375229763464171842707250380098325357985598834033987924257831653058727593418140233809822646636739078353499385867729693854884921341655109475107063186115423904590431267170371701195815230285084782893452791122869608103439206392462812241680332739759276556510921929853509576501742266889691406971962061348677605264432024987342397008600920140628487, 3],
[25701669250559171042787620803978097359929521626945208470038327164808519143184821340338359956652927376497510456350825779128774481070155738263674646919350713271307106263047192753652560872693847025375343405491538186238144355941186816744279446155441697909221615479577488056649915901733556869635627909699033627583539526199954349261141009124641940449027603330724930673094897139365007622928099240337416834217850541514518460417759857852966815452279972345835110548963130027518620736546412435414857305364581529518581592701170264629922407977436795947980294927322827461226980362295764476541511988714241411870754571769741408746627, 2],
]
OtPKB = random.choice(OtPK)
OtPKB_index = OtPK.index(OtPKB)
OtPK_pub = expo(DH_g, OtPKB[0], DH_p)


class Keys:
    id_pub = None
    sigPK_pub = None
    sign_SigPK_pub = None
    eph_pub = None
    otPK_pub = None


#Envoi des clés au serveur
keys_bundle = Keys()
keys_bundle.id_pub = ID_pub
keys_bundle.sigPK_pub = SigPK_pub
keys_bundle.sign_SigPK_pub = Sign_SigPK_pub
keys_bundle.eph_pub = Eph_pub
keys_bundle.otPK_pub = OtPK_pub

socket.send(pickle.dumps(keys_bundle))

#Reception des clés d'Alice du serveur
alice_pub_keys = pickle.loads(socket.recv(BUFF_SIZE))

#Verification de la signature d'Alice
assert verif_rsa(alice_pub_keys.sigPK_pub, alice_pub_keys.sign_SigPK_pub, alice_pub_keys.id_pub)

DH1 = expo(alice_pub_keys.sigPK_pub, ID_pub[1],  DH_p)
DH2 = expo(expo(DH_g, alice_pub_keys.id_pub[1], DH_p), Eph, DH_p)
DH3 = expo(alice_pub_keys.sigPK_pub, Eph, DH_p)
DH4 = expo(alice_pub_keys.otPK_pub, Eph, DH_p)

SK = str(DH1) + str(DH2) + str(DH3) + str(DH4)


#Demarrage des interactions
envoi = Thread(target=Send, args=[socket])
recep = Thread(target=Reception, args=[socket])


envoi.start()
recep.start()