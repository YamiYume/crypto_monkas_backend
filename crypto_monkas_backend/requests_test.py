from requests import get, post

ex1 = """I found myself within a forest dark, for the straightfoward pathway had been lost.
         Ah me! How hard a thing is to say, what was this forest savage, rough, and stern,
         which in the very thought renews the fear. So bitter is it, death is little more..."""

ex2 = """I am writing this under an appreciable mental strain, since by tonight I shall be no more.
         Penniless, and at the end of my supply of the drug which alone makes life endurable, I can
         bear the torture no longer; and shall cast myself from this garret window into the squalid
         street below. Do not think from my slavery to morphine that I am a weakling or a degenerate.
         When you have read these hastily scrawled pages you may guess, though never fully realise,
         why it is that I must have forgetfulness or death. It was in one of the most open and least
         frequented parts of the broad Pacific that the packet of which I was supercargo fell a victim
         to the German sea-raider. The great war was then at its very beginning, and the ocean forces of
         the Hun had not completely sunk to their later degradation; so that our vessel was made a legitimate prize,
         whilst we of her crew were treated with all the fairness and consideration due us as naval prisoners.
         So liberal, indeed, was the discipline of our captors, that five days after we were taken I managed
         to escape alone in a small boat with water and provisions for a good length of time. When I finally found
         myself adrift and free, I had but little idea of my surroundings. Never a competent navigator,
         I could only guess vaguely by the sun and stars that I was somewhat south of the equator. Of the longitude
         I knew nothing, and no island or coast-line was in sight. The weather kept fair, and for uncounted days I
         drifted aimlessly beneath the scorching sun; waiting either for some passing ship,or to be cast on the shores
         of some habitable land. But neither ship nor land appeared, and I began to despair in my solitude upon the heaving
         vastnesses of unbroken blue. The change happened whilst I slept. Its details I shall never know; for my slumber,
         though troubled and dream-infested, was continuous. When at last I awaked, it was to discover myself half sucked
         into a slimy expanse of hellish black mire which extended about me in monotonous undulations as far as I could see,
         and in which my boat lay grounded some distance away. Though one might well imagine that my first sensation would be
         of wonder at so prodigious and unexpected a transformation of scenery, I was in reality more horrified than astonished;
         for there was in the air and in the rotting soil a sinister quality which chilled me to the very core.
         The region was putrid with the carcasses of decaying fish, and of other less describable things which I saw protruding 
         from the nasty mud of the unending plain. Perhaps I should not hope to convey in mere words the unutterable
         hideousness that can dwell in absolute silence and barren immensity. There was nothing within hearing, and
         nothing in sight save a vast reach of black slime; yet the very completeness of the stillness and the homogeneity of the
         landscape oppressed me with a nauseating fear. The sun was blazing down from a sky which seemed to me almost black in its
         cloudless cruelty; as though reflecting the inky marsh beneath my feet. As I crawled into the stranded boat
         I realised that only one theory could explain my position. Through some unprecedented volcanic upheaval,a portion of
         the ocean floor must have been thrown to the surface, exposing regions which for innumerable millions of years had lain
         hidden under unfathomable watery depths. So great was the extent of the new land which had risen beneath me, that I could
         not detect the faintest noise of the surging ocean, strain my ears as I might. Nor were there any sea-fowl to prey upon the
         dead things. For several hours I sat thinking or brooding in the boat, which lay upon its side and afforded a slight shade as
         the sun moved across the heavens. As the day progressed, the ground lost some of its stickiness, and seemed likely to dry sufficiently
         for travelling purposes in a short time. That night I slept but little, and the next day I made for myself a pack
         containing food and water, preparatory to an overland journey in search of the vanished sea and possible rescueself.
         On the third morning I found the soil dry enough to walk upon with ease. The odour of the fish was maddening;
         but I was too much concerned with graver things to mind so slight an evil, and set out boldly for an unknown goal. All
         day I forged steadily westward, guided by a far-away hummock which rose higher than any other elevation on the rolling
         desert. That night I encamped, and on the following day still travelled toward the hummock, though that object seemed
         scarcely nearer than when I had first espied it. By the fourth evening I attained the base of the mound, which turned out
         to be much higher than it had appeared from a distance; an intervening valley setting it out in sharper relief from the general
         surface. Too weary to ascend, I slept in the shadow of the hill."""


an1 = """DAJPIYHTNZGARDOCDIVAJMZNOYVMFAJMOCZNOMVDBCOAJRVMYKVOCRVTCVYWZZIGJNOVCHZCJRCVMYVOCD
         IBDNOJNVTRCVORVNOCDNAJMZNONVQVBZMJPBCVIYNOZMIRCDXCDIOCZQZMTOCJPBCOMZIZRNOCZAZVMNJW
         DOOZMDNDOYZVOCDNGDOOGZHJMZ"""

an2 = """JQMVTASWOFJCURZUVIJQBOWRTIBKJQBRZOWRBIUEZRJQCIBTLIRZCISZITDOOVFQWRIZAOZQCZIBTIRZUV
         EUWRQWISCZIRCIWRZUWJQBOWRWIHIEOBQMEZIVTWROBVCZUYZUVRZOHOBSRZQMEZRBOVOCWRZOJOIBWQDU
         RROBUWURTOIRZUWFURRFOAQBO"""

an3 = """JIPVQGNZTFOIXJWKJQCIPUFTWGCULIPUWKFTWUCJHKWIPXCUGSCWKXCZKCGEFFQOPTWCKNFKPXKCUGCWKJ
         QHJTWPTCZXKCWXCTWKJTIPUFTWTCYCHFUPVHKCQGTWFUQXKJDKJQWKFYFUZWKPVHKWUFQFXTWKFIFCUTPE
         JWWFUJTJWGFCWKJTOJWWOFNPUF"""

an4 = """CTUHLBBTHZBSCLCYXXZLHTXALXKTUUTPGXVEUEAELTQYMBVNYUGEIGQRBMQDBTTWVXVZGHZPJXVYCEMDMT
         VOUMBSYXVOIYUJMNXAFRWQNAMOLNOHBBKSUEWYYFIVYLTTZXMYXNZLVEMTWTVMYTZEBXBZLMCCYGWWIGOP
         LTVOMAIWFVIDNFGDYENQLHUEBBARUKZPNPQYXHETHMWEBXABOTTTXLBCYXBMYEWHXHVZNMPTHDNCIFUJME
         IGYKGEIFWCJAQYYMPLNBIXUPMLEEQYAHZLXXOPHXZLNXESYGGZOAIGYKMLXMPPMXPLMMQWSLKCUPTPXIIR
         YLGZOFIJANMDMMPZOZPYYOMCZNTWSKMLFBAPQAGTNBAEBTBTGNAEBTDPZHZRYMNFFGMDMHZOYTBSCMELMB
         VZHXWQNAMXILBZJXVLHWTPULBQLXYFYGBPXIICNLWQNAMMLHIOJTKTZBKEBTBEBXXLWDMEIYESCVPTQTAD
         OIMCWTZRIYMWFTDTWMQXNHBSYZMCGTVDYTZLCWMCNAMRLXIEQTZHULBSYGIECMAGYKGMYZQYHBVRUGLEBX
         WNYTVQIKKPMHNEBXPFHAIOHHBNIFXWYMMWSLCYEMWEBXQCFTBPLWMRLTLLNBWYMHBSUMWFLOMDMXTHULUL
         XXIWYZQECFIEYIZTTXESCEAEQXWQBXZNLXEHYKMELXIEYWETNAIWFMPPZTQCHXADUGLNIGATXXZLNBWYXN
         MFMTAYUOIWJKQDIGMCMLWWCUMCUEQYXXMOQTAEBXLTMVQAFBVPIYWFLVIANHZDNAIEZBDPXTGDUYBPLPMH
         YKMEUDMYCFIYUZMONHMDWTXPUEWYYBVLMFIWFUWLNPQEBPIEYKIYXIZZPBATIGAQIKIRIHLWYGOEBHNECF
         MHBXVTZBVLFEGQINVOGRAPFYIOLBNEUGLQLXMTBTLMOMTTNMTPCWMLIYUJMNZCINVOCGODHXDPLTKZGIME
         YGBYUOQRUMWCCVWFFWWYFROFYLAGUZCPFRJJNAMDOGIYXLBLLLBSUMQHULAZGXESUMAZOMPZZMPPYJCLNH
         ZZZMPPFHVRCMCOYBSYYPVZNAQYATVOHHQDFTVOIKKZULBWCGMHULQYMBOSNMPPQXIEBXZVYIBQUBZLHWNZ
         LNVNINVEYWLLSLQOLBNEYWITGEMDMEGMYGMLNABSYLKZLVPTHZAFHPITNBVRYBBSYKNZLLWXYIIDMBVRMA
         QAIKBZVXKLMMWYNAMDBHZPMHNDIFMSUUQEUUTPFTVOVNBYYBBSYKASCIVZLEIYXTXAYTZPXTVOCUMRUGBZ
         XXAAUBZTHFGDIEQEOWMFJHVEBXPPUOQYAOIDNGMDMXAZZNVMLHSPHUTFYMPPWAIYAXPLJIMYYWESCEAECL
         TPJMQEMWMEUBTDCLPLFEVPPXZVHHEQIKUJMECXVXZEBHCRBMZZOUTPXTVOXKMLGBVQYLBPXPIDWHVECGCZ
         OLESYGIEFTAECTELEXLTNPIDNHLTMVWGYKUJMXTQBTTQMNKVYWQYNHIDFBUJYQXLHLMZZAMWFBASVEINEF
         QCYPPTWAMINXVOYWIMINBXYBVXIGWEIGWFMNVOOEIECHVDULNLLTATWHCWXLMPUGLTHPPTWAUJVHIEFTGR
         LHCYXXLDIFMOCLBLHVMLQTGEBHCRBHVPGBOSNPMWFBULABVPNAIEGRNTLLBDYGALNBWYQHCWXUMZZPWYXX
         ZLNLWALHLTABWFMTVOOGMIJXKEYWIELTVDZHZXUMQZHHNDWXVPLRQHULQYLXIWCMGXIKMSIKZTZBMONAIY
         ULBZHBASYWNZLMPPLXELMBVEBXITLTVOCGBSYKWENBVRMHQWULQYCLBPLJCLFBBJQAQNBVPTFEMOGXBZNA
         MGYKGNIKMEBXZPABWYQTAAOMZTXPQEBMPPWTZNULAPMHNOYVIJCGOQCLPLHWWQIMPPLEMDMWMDWKQMUUTP
         NAQYALESCVPTMTEALHBCOWQYAYZZGMPPHTAESFCOIYBSYNVPHWQYAITLCGXPLAIAMBASINTOHHBSIIMEIV
         WYPXGTHFMCYPWCXLBSYNVFNMMCUUTPBBLPINAYYLAEBTBNUGLHYETTHTJDIECEYLQWYGKPUGLMUKZPHBUX
         YGATNRBSYKMHULVZNAQYAPQEBBVSYTZTHZIYXGWEBBVRCGATAABDUOMLPTAELXINBHNMFTKVMEQXYRMENA
         MGYKGNIFXWYMMYYLAZZMPPMMQWFGMDMTVONAMSIFWRYGMTNRWQNAMWUGLDWTXPIIXCYLAPXFMHCMPLHTCD
         YTBTHZNPUKBSYLCYQTAMFTHTHZLZQGNCIFIDERESCVPDYXUPXMWXYTTXILBMFTKVCGQEMVTZOWTPMLKCOX
         TESTAEBHCRBKMQFXKECGOEBXQYERULLLPMYGMLNAUJZXMEULQNLTEWYWQYNHBSYLBCUGLPXUWLNBZPUEQD
         YWBSUMWYFRWYYMPPIKGNINTOYQXWUBVXSIWDCMQZHMPCINOSMHUPOGXCYVMOYGBPXOWWWTVTWNXSYTDLFT
         XZLMQZHHNEBXWNYTVQFHWCGNAEBTDPVXMYNAZZQGBZNAMDOKNLWXMIJHATHZZPABWYMPPTWANZLBVYOFMC
         UUTPGBTWCHVDIYGPUKASUWTLCGPTXWMYOGLPLNVQUMPZGTJWYPIEYKGOYIBSMLWRLXIEQTAEBXMINXVEIY
         BSYGMHFTVOQAQNBAIOLBAPHUMYYTBSGXBSUMQNINTOHHBOYMMNNMPPZTQYNXAEHHQDYHNEBXAFLZQYAHKP
         UGAELTQYGRMLLLIDCFQRBMVZLPMCYMPPLXIYSLMLZHEWNHXCYRCAIGBSYWMLXMPTHZAQIKAPPXZLFAWFLL
         QDUMBSCGSTHZWCVKWZXBVRCGBSYUWLNPPTWATLSNXZHBBDMBLPUGLLZYWCXXLLMEQRBMASUWMLMMPPMNVX
         IOMOUVZZMLBSYAMLPXVDULBSYWIJJKWRLXADYWBSYZZZOGLWILBDIFMZZBBDMMQNEBVPMLIYXLMPGXLWCD
         MWSMWOLRAFZYQNCXVEFRNZLMZLPXTWCGOAOKXZMXATHTASIKBECFMEBTBYCZPECLTPJMJFNEQENEMLHWBS
         YGMINWIJCFIOYYWCGRAPFYIAUVSNIGBLCGQYAYWZXTVOQTBPLIZPJTZLNHZJNHIYIOMCFTVODHCCHXGTHL
         MLLVPZZMPPPTVTMAMOMXILHWXZMLQMFXZPMVCPIGBSYMPTLWUZLGQYABNZOGLEBXAZCELCSXVZOZPEIPIW
         ENXZHPQEBXIDYMPPIWWFLHNEBXNTMAELMFIOXXVTHZJFNBELMMWZGNKSWHVNYKVPXPQEBZZLPXZEBBVRMM
         WXCGLDILTTAABLHXDTFTVOMXBZOMJZFWTJZHZLHNVVHHEYAHIWUETOURQQIKOPXLBPUWQWSPMDNPICXZCT
         XXLMSTNLLTELSACXGHKVQAQNBKWDYAQRBXZEBTVLHRWEBXZPFXDLNBWYIGBSYKWWFBVRXXAPLMBSUMVTAA
         BTYGKLGIMOUGLZHMPPZHTWIPQYAWIJMMQWFMZLPXTWYWBZQTZONAMSOFUZWDBSINOSNAIEIURPWMAPYFMO
         MVICWXTJHXICYKBSUGESYGQSUWNTLLBPMIQPXBBMSMPPZHCCNAMGYGQYABIENTQYYWBSYUIDYHNEBXUZOG
         LHBBKSNNZYYWWFNMWMYFCNBAQRBXZEBTVTNAIOUIXPUKMOZKWXUWQDNTVNYTVTHMMCPXVTHZDLFEMJMXBE
         CGOTNHCECGASUKXPLKMWCXNQLHUEBXOPHXZLFLCCZTKPNHWHYTZJNHIDWXVOCLTPJMQYNAMDBTLZQHNEBX
         PTFE"""

an5 = """NOUFIEYSMDTWIFLFNAIHTESROFRKADETHROIRATSOTFHGPRDAWAHWTABADHYONLEEMAHTSHOWH
        ETDARAINGIHAOSTSTHAWYHSTAWRFOSIATSSERGEAVAGHUOESTDNIWHNRTINHCRVEEHUHOTYETR
        HGTWSENAFEEHIOBSRIERTTETDISSHITALTTILEORMESXWRI"""

ROOT = "http://localhost:5000/"


def shift_test():
    print("shift tests")
    tests_enc = [
        ("abcdefg", "a"),
        ("12345", "12"),
        ("abcdef", "54"),
        (ex1, "177"),
    ]
    tests_dec = [
        ("CDEFGH", "a"),
        ("12345", "12"),
        ("CDEFGH", "54"),
        (an1, "177"),
    ]
    tests_atk = [
        (an1, "a"),
        (an1, "3"),
    ]
    print("encryptions_tests")
    for test in tests_enc:
        print(
            get(ROOT + "shift/enc", json={"plaintext": test[0], "key": test[1]}).json()
        )
    print("decryption_tests")
    for test in tests_dec:
        print(
            get(ROOT + "shift/dec", json={"ciphertext": test[0], "key": test[1]}).json()
        )
    print("attack_tests")
    for test in tests_atk:
        print(
            get(
                ROOT + "shift/atk", json={"ciphertext": test[0], "head": test[1]}
            ).json()
        )


def afin_test():
    print("afin tests")
    tests_enc = [
        ("abcdefg", "a"),
        ("abcdefg", "15"),
        ("abcdefg", "15 a"),
        ("abcdefg", "13 15"),
        ("12345", "15 5"),
        ("abcdef", "55 25"),
        (ex1, "177 34"),
    ]
    tests_dec = [
        ("ZCFILO", "a"),
        ("ZCFILO", "15"),
        ("ZCFILO", "15 a"),
        ("ZCFILO", "13 15"),
        ("12345", "15 5"),
        ("ZCFILO", "55 25"),
        (an2, "177 34"),
    ]
    tests_atk = [
        (an2, "a"),
        (an2, "3"),
    ]
    print("encryptions_tests")
    for test in tests_enc:
        print(
            get(ROOT + "afin/enc", json={"plaintext": test[0], "key": test[1]}).json()
        )
    print("decryption_tests")
    for test in tests_dec:
        print(
            get(ROOT + "afin/dec", json={"ciphertext": test[0], "key": test[1]}).json()
        )
    print("attack_tests")
    for test in tests_atk:
        print(
            get(ROOT + "afin/atk", json={"ciphertext": test[0], "head": test[1]}).json()
        )


def subs_test():
    print("subs tests")
    tests_enc = [
        ("abcdefg", "12345678901234567890123456"),
        ("abcdefg", "bcdefg"),
        ("12345", "bcdefghijklmnopqrstuvwxyza"),
        ("abcdef", "cedgfihkjmlonqpsrutwvyxazb"),
        (ex1, "cedgfihkjmlonqpsrutwvyxazb"),
    ]
    tests_dec = [
        ("CEDGFI", "12345678901234567890123456"),
        ("CEDGFI", "bcdefg"),
        ("12345", "bcdefghijklmnopqrstuvwxyza"),
        ("CEDGFI", "cedgfihkjmlonqpsrutwvyxazb"),
        (an3, "cedgfihkjmlonqpsrutwvyxazb"),
    ]
    tests_atk = [
        ("",),
        (an3,),
    ]
    print("encryptions_tests")
    for test in tests_enc:
        print(
            get(ROOT + "subs/enc", json={"plaintext": test[0], "key": test[1]}).json()
        )
    print("decryption_tests")
    for test in tests_dec:
        print(
            get(ROOT + "subs/dec", json={"ciphertext": test[0], "key": test[1]}).json()
        )
    print("attack_tests")
    for test in tests_atk:
        print(get(ROOT + "subs/atk", json={"ciphertext": test[0]}).json())


def vig_test():
    print("vig tests")
    tests_enc = [
        ("12345", "12"),
        ("abcdef", "BC"),
        (ex2, "UTIL DAY"),
    ]
    tests_dec = [
        ("12345", "12"),
        ("BDDFFH", "BC"),
        (an4, "UTIL DAY"),
    ]
    tests_atk = [
        (an4, "5"),
    ]
    print("encryptions_tests")
    for test in tests_enc:
        print(get(ROOT + "vig/enc", json={"plaintext": test[0], "key": test[1]}).json())
    print("decryption_tests")
    for test in tests_dec:
        print(
            get(ROOT + "vig/dec", json={"ciphertext": test[0], "key": test[1]}).json()
        )
    print("attack_tests")
    for test in tests_atk:
        print(
            get(ROOT + "vig/atk", json={"ciphertext": test[0], "head": test[1]}).json()
        )


def perm_test():
    print("perm tests")
    tests_enc = [
        ("abcdef", "BC"),
        ("12345", "5 3 4 2 1"),
        ("abcdef", "5 3 4 2 1"),
        (ex1, "5 3 4 2 1"),
    ]
    tests_dec = [
        ("ECDBAF", "BC"),
        ("12345", "5 3 4 2 1"),
        ("ECDBAF", "5 3 4 2 1"),
        (an5, "5 3 4 2 1"),
    ]
    tests_atk = []
    print("encryptions_tests")
    for test in tests_enc:
        print(
            get(ROOT + "perm/enc", json={"plaintext": test[0], "key": test[1]}).json()
        )
    print("decryption_tests")
    for test in tests_dec:
        print(
            get(ROOT + "perm/dec", json={"ciphertext": test[0], "key": test[1]}).json()
        )
    print("attack_tests")
    for test in tests_atk:
        print(
            get(ROOT + "perm/atk", json={"ciphertext": test[0], "head": test[1]}).json()
        )


if __name__ == "__main__":
    shift_test()
    afin_test()
    subs_test()
    vig_test()
    perm_test()
    print(
        post(
            ROOT + "hill/enc/Cat.png/12 13 11 25 72 23 43 3 11",
            files={"file": open("test_files/Cat.png", "rb")},
        ).json()
    )
    print(
        post(
            ROOT + "hill/dec/encCat.png/12 13 11 25 72 23 43 3 11",
            files={"file": open("test_files/encCat.png", "rb")},
        ).json()
    )
