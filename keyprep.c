#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "keyprep.h"
#include "util.h"
#include "Random.h"
#include <gmp.h>
#include "gmpecc.h"

// Random number function from Random.h
extern void generate_strpublickey(struct Point *publickey, bool compress, char *dst);
extern void set_publickey(char *param, struct Point *publickey);

static int get_random_index(int max)
{
    return (int)(rnd() * max);
}

// You can paste all your group definitions here
const char *group_1_values[] = {
    "16",
    "32",
    "48",
    "64",
    "80",
    "96",
    "112",
    "128",
    "144",
    "160",
    "176",
    "192",
    "208",
    "224",
    "240",
};

// Group 2
const char *group_2_values[] = {
    "256",
    "512",
    "768",
    "1024",
    "1280",
    "1536",
    "1792",
    "2048",
    "2304",
    "2560",
    "2816",
    "3072",
    "3328",
    "3584",
    "3840",
};

// Group 3
const char *group_3_values[] = {
    "4096",
    "8192",
    "12288",
    "16384",
    "20480",
    "24576",
    "28672",
    "32768",
    "36864",
    "40960",
    "45056",
    "49152",
    "53248",
    "57344",
    "61440",
};

// Group 4
const char *group_4_values[] = {
    "65536",
    "131072",
    "196608",
    "262144",
    "327680",
    "393216",
    "458752",
    "524288",
    "589824",
    "655360",
    "720896",
    "786432",
    "851968",
    "917504",
    "983040",
};

// Group 5
const char *group_5_values[] = {
    "1048576",
    "2097152",
    "3145728",
    "4194304",
    "5242880",
    "6291456",
    "7340032",
    "8388608",
    "9437184",
    "10485760",
    "11534336",
    "12582912",
    "13631488",
    "14680064",
    "15728640",
};

// Group 6
const char *group_6_values[] = {
    "16777216",
    "33554432",
    "50331648",
    "67108864",
    "83886080",
    "100663296",
    "117440512",
    "134217728",
    "150994944",
    "167772160",
    "184549376",
    "201326592",
    "218103808",
    "234881024",
    "251658240",
};

// Group 7
const char *group_7_values[] = {
    "268435456",
    "536870912",
    "805306368",
    "1073741824",
    "1342177280",
    "1610612736",
    "1879048192",
    "2147483648",
    "2415919104",
    "2684354560",
    "2952790016",
    "3221225472",
    "3489660928",
    "3758096384",
    "4026531840",
};

// Group 8
const char *group_8_values[] = {
    "4294967296",
    "8589934592",
    "12884901888",
    "17179869184",
    "21474836480",
    "25769803776",
    "30064771072",
    "34359738368",
    "38654705664",
    "42949672960",
    "47244640256",
    "51539607552",
    "55834574848",
    "60129542144",
    "64424509440",
};

// Group 9
const char *group_9_values[] = {
    "68719476736",
    "137438953472",
    "206158430208",
    "274877906944",
    "343597383680",
    "412316860416",
    "481036337152",
    "549755813888",
    "618475290624",
    "687194767360",
    "755914244096",
    "824633720832",
    "893353197568",
    "962072674304",
    "1030792151040",
};

// Group 10
const char *group_10_values[] = {
    "1099511627776",
    "2199023255552",
    "3298534883328",
    "4398046511104",
    "5497558138880",
    "6597069766656",
    "7696581394432",
    "8796093022208",
    "9895604649984",
    "10995116277760",
    "12094627905536",
    "13194139533312",
    "14293651161088",
    "15393162788864",
    "16492674416640",
};

// Group 11
const char *group_11_values[] = {
    "17592186044416",
    "35184372088832",
    "52776558133248",
    "70368744177664",
    "87960930222080",
    "105553116266496",
    "123145302310912",
    "140737488355328",
    "158329674399744",
    "175921860444160",
    "193514046488576",
    "211106232532992",
    "228698418577408",
    "246290604621824",
    "263882790666240",
};

// Group 12
const char *group_12_values[] = {
    "281474976710656",
    "562949953421312",
    "844424930131968",
    "1125899906842624",
    "1407374883553280",
    "1688849860263936",
    "1970324836974592",
    "2251799813685248",
    "2533274790395904",
    "2814749767106560",
    "3096224743817216",
    "3377699720527872",
    "3659174697238528",
    "3940649673949184",
    "4222124650659840",
};

// Group 13
const char *group_13_values[] = {
    "4503599627370496",
    "9007199254740992",
    "13510798882111488",
    "18014398509481984",
    "22517998136852480",
    "27021597764222976",
    "31525197391593472",
    "36028797018963968",
    "40532396646334464",
    "45035996273704960",
    "49539595901075456",
    "54043195528445952",
    "58546795155816448",
    "63050394783186944",
    "67553994410557440",
};

// Group 14
const char *group_14_values[] = {
    "72057594037927936",
    "144115188075855872",
    "216172782113783808",
    "288230376151711744",
    "360287970189639680",
    "432345564227567616",
    "504403158265495552",
    "576460752303423488",
    "648518346341351424",
    "720575940379279360",
    "792633534417207296",
    "864691128455135232",
    "936748722493063168",
    "1008806316530991104",
    "1080863910568919040",
};

// Group 15
const char *group_15_values[] = {
    "1152921504606846976",
    "2305843009213693952",
    "3458764513820540928",
    "4611686018427387904",
    "5764607523034234880",
    "6917529027641081856",
    "8070450532247928832",
    "9223372036854775808",
    "10376293541461622784",
    "11529215046068469760",
    "12682136550675316736",
    "13835058055282163712",
    "14987979559889010688",
    "16140901064495857664",
    "17293822569102704640",
};

// Group 16
const char *group_16_values[] = {
    "18446744073709551616",
    "36893488147419103232",
    "55340232221128654848",
    "73786976294838206464",
    "92233720368547758080",
    "110680464442257309696",
    "129127208515966861312",
    "147573952589676412928",
    "166020696663385964544",
    "184467440737095516160",
    "202914184810805067776",
    "221360928884514619392",
    "239807672958224171008",
    "258254417031933722624",
    "276701161105643274240",
};

// Group 17
const char *group_17_values[] = {
    "295147905179352825856",
    "590295810358705651712",
    "885443715538058477568",
    "1180591620717411303424",
    "1475739525896764129280",
    "1770887431076116955136",
    "2066035336255469780992",
    "2361183241434822606848",
    "2656331146614175432704",
    "2951479051793528258560",
    "3246626956972881084416",
    "3541774862152233910272",
    "3836922767331586736128",
    "4132070672510939561984",
    "4427218577690292387840",
};

// Group 18
const char *group_18_values[] = {
    "4722366482869645213696",
    "9444732965739290427392",
    "14167099448608935641088",
    "18889465931478580854784",
    "23611832414348226068480",
    "28334198897217871282176",
    "33056565380087516495872",
    "37778931862957161709568",
    "42501298345826806923264",
    "47223664828696452136960",
    "51946031311566097350656",
    "56668397794435742564352",
    "61390764277305387778048",
    "66113130760175032991744",
    "70835497243044678205440",
};

// Group 19
const char *group_19_values[] = {
    "75557863725914323419136",
    "151115727451828646838272",
    "226673591177742970257408",
    "302231454903657293676544",
    "377789318629571617095680",
    "453347182355485940514816",
    "528905046081400263933952",
    "604462909807314587353088",
    "680020773533228910772224",
    "755578637259143234191360",
    "831136500985057557610496",
    "906694364710971881029632",
    "982252228436886204448768",
    "1057810092162800527867904",
    "1133367955888714851287040",
};

// Group 20
const char *group_20_values[] = {
    "1208925819614629174706176",
    "2417851639229258349412352",
    "3626777458843887524118528",
    "4835703278458516698824704",
    "6044629098073145873530880",
    "7253554917687775048237056",
    "8462480737302404222943232",
    "9671406556917033397649408",
    "10880332376531662572355584",
    "12089258196146291747061760",
    "13298184015760920921767936",
    "14507109835375550096474112",
    "15716035654990179271180288",
    "16924961474604808445886464",
    "18133887294219437620592640",
};

// Group 21
const char *group_21_values[] = {
    "19342813113834066795298816",
    "38685626227668133590597632",
    "58028439341502200385896448",
    "77371252455336267181195264",
    "96714065569170333976494080",
    "116056878683004400771792896",
    "135399691796838467567091712",
    "154742504910672534362390528",
    "174085318024506601157689344",
    "193428131138340667952988160",
    "212770944252174734748286976",
    "232113757366008801543585792",
    "251456570479842868338884608",
    "270799383593676935134183424",
    "290142196707511001929482240",
};

// Group 22
const char *group_22_values[] = {
    "309485009821345068724781056",
    "618970019642690137449562112",
    "928455029464035206174343168",
    "1237940039285380274899124224",
    "1547425049106725343623905280",
    "1856910058928070412348686336",
    "2166395068749415481073467392",
    "2475880078570760549798248448",
    "2785365088392105618523029504",
    "3094850098213450687247810560",
    "3404335108034795755972591616",
    "3713820117856140824697372672",
    "4023305127677485893422153728",
    "4332790137498830962146934784",
    "4642275147320176030871715840",
};

// Group 23
const char *group_23_values[] = {
    "4951760157141521099596496896",
    "9903520314283042199192993792",
    "14855280471424563298789490688",
    "19807040628566084398385987584",
    "24758800785707605497982484480",
    "29710560942849126597578981376",
    "34662321099990647697175478272",
    "39614081257132168796771975168",
    "44565841414273689896368472064",
    "49517601571415210995964968960",
    "54469361728556732095561465856",
    "59421121885698253195157962752",
    "64372882042839774294754459648",
    "69324642199981295394350956544",
    "74276402357122816493947453440",
};

// Group 24
const char *group_24_values[] = {
    "79228162514264337593543950336",
    "158456325028528675187087900672",
    "237684487542793012780631851008",
    "316912650057057350374175801344",
    "396140812571321687967719751680",
    "475368975085586025561263702016",
    "554597137599850363154807652352",
    "633825300114114700748351602688",
    "713053462628379038341895553024",
    "792281625142643375935439503360",
    "871509787656907713528983453696",
    "950737950171172051122527404032",
    "1029966112685436388716071354368",
    "1109194275199700726309615304704",
    "1188422437713965063903159255040",
};

// Group 25
const char *group_25_values[] = {
    "1267650600228229401496703205376",
    "2535301200456458802993406410752",
    "3802951800684688204490109616128",
    "5070602400912917605986812821504",
    "6338253001141147007483516026880",
    "7605903601369376408980219232256",
    "8873554201597605810476922437632",
    "10141204801825835211973625643008",
    "11408855402054064613470328848384",
    "12676506002282294014967032053760",
    "13944156602510523416463735259136",
    "15211807202738752817960438464512",
    "16479457802966982219457141669888",
    "17747108403195211620953844875264",
    "19014759003423441022450548080640",
};

// Group 26
const char *group_26_values[] = {
    "20282409603651670423947251286016",
    "40564819207303340847894502572032",
    "60847228810955011271841753858048",
    "81129638414606681695789005144064",
    "101412048018258352119736256430080",
    "121694457621910022543683507716096",
    "141976867225561692967630759002112",
    "162259276829213363391578010288128",
    "182541686432865033815525261574144",
    "202824096036516704239472512860160",
    "223106505640168374663419764146176",
    "243388915243820045087367015432192",
    "263671324847471715511314266718208",
    "283953734451123385935261518004224",
    "304236144054775056359208769290240",
};

// Group 27
const char *group_27_values[] = {
    "324518553658426726783156020576256",
    "649037107316853453566312041152512",
    "973555660975280180349468061728768",
    "1298074214633706907132624082305024",
    "1622592768292133633915780102881280",
    "1947111321950560360698936123457536",
    "2271629875608987087482092144033792",
    "2596148429267413814265248164610048",
    "2920666982925840541048404185186304",
    "3245185536584267267831560205762560",
    "3569704090242693994614716226338816",
    "3894222643901120721397872246915072",
    "4218741197559547448181028267491328",
    "4543259751217974174964184288067584",
    "4867778304876400901747340308643840",
};

// Group 28
const char *group_28_values[] = {
    "5192296858534827628530496329220096",
    "10384593717069655257060992658440192",
    "15576890575604482885591488987660288",
    "20769187434139310514121985316880384",
    "25961484292674138142652481646100480",
    "31153781151208965771182977975320576",
    "36346078009743793399713474304540672",
    "41538374868278621028243970633760768",
    "46730671726813448656774466962980864",
    "51922968585348276285304963292200960",
    "57115265443883103913835459621421056",
    "62307562302417931542365955950641152",
    "67499859160952759170896452279861248",
    "72692156019487586799426948609081344",
    "77884452878022414427957444938301440",
};

// Group 29
const char *group_29_values[] = {
    "83076749736557242056487941267521536",
    "166153499473114484112975882535043072",
    "249230249209671726169463823802564608",
    "332306998946228968225951765070086144",
    "415383748682786210282439706337607680",
    "498460498419343452338927647605129216",
    "581537248155900694395415588872650752",
    "664613997892457936451903530140172288",
    "747690747629015178508391471407693824",
    "830767497365572420564879412675215360",
    "913844247102129662621367353942736896",
    "996920996838686904677855295210258432",
    "1079997746575244146734343236477779968",
    "1163074496311801388790831177745301504",
    "1246151246048358630847319119012823040",
};

// Group 30
const char *group_30_values[] = {
    "1329227995784915872903807060280344576",
    "2658455991569831745807614120560689152",
    "3987683987354747618711421180841033728",
    "5316911983139663491615228241121378304",
    "6646139978924579364519035301401722880",
    "7975367974709495237422842361682067456",
    "9304595970494411110326649421962412032",
    "10633823966279326983230456482242756608",
    "11963051962064242856134263542523101184",
    "13292279957849158729038070602803445760",
    "14621507953634074601941877663083790336",
    "15950735949418990474845684723364134912",
    "17279963945203906347749491783644479488",
    "18609191940988822220653298843924824064",
    "19938419936773738093557105904205168640",
};

// Group 31
const char *group_31_values[] = {
    "21267647932558653966460912964485513216",
    "42535295865117307932921825928971026432",
    "63802943797675961899382738893456539648",
    "85070591730234615865843651857942052864",
    "106338239662793269832304564822427566080",
    "127605887595351923798765477786913079296",
    "148873535527910577765226390751398592512",
    "170141183460469231731687303715884105728",
    "191408831393027885698148216680369618944",
    "212676479325586539664609129644855132160",
    "233944127258145193631070042609340645376",
    "255211775190703847597530955573826158592",
    "276479423123262501563991868538311671808",
    "297747071055821155530452781502797185024",
    "319014718988379809496913694467282698240",
};

// Group 32
const char *group_32_values[] = {
    "340282366920938463463374607431768211456",
    "680564733841876926926749214863536422912",
    "1020847100762815390390123822295304634368",
    "1361129467683753853853498429727072845824",
    "1701411834604692317316873037158841057280",
    "2041694201525630780780247644590609268736",
    "2381976568446569244243622252022377480192",
    "2722258935367507707706996859454145691648",
    "3062541302288446171170371466885913903104",
    "3402823669209384634633746074317682114560",
    "3743106036130323098097120681749450326016",
    "4083388403051261561560495289181218537472",
    "4423670769972200025023869896612986748928",
    "4763953136893138488487244504044754960384",
    "5104235503814076951950619111476523171840",
};

// Group 33
const char *group_33_values[] = {
    "5444517870735015415413993718908291383296",
    "10889035741470030830827987437816582766592",
    "16333553612205046246241981156724874149888",
    "21778071482940061661655974875633165533184",
    "27222589353675077077069968594541456916480",
    "32667107224410092492483962313449748299776",
    "38111625095145107907897956032358039683072",
    "43556142965880123323311949751266331066368",
    "49000660836615138738725943470174622449664",
    "54445178707350154154139937189082913832960",
    "59889696578085169569553930907991205216256",
    "65334214448820184984967924626899496599552",
    "70778732319555200400381918345807787982848",
    "76223250190290215815795912064716079366144",
    "81667768061025231231209905783624370749440",
};

#define GROUP_SIZE 15
#define MAX_PATH_LENGTH 10000

const char *get_random_decimal(const char **group, int group_size)
{
    int index = get_random_index(group_size);
    return group[index];
}

// Helper function to perform a single subtraction
static bool subtract_from_point(struct Point *point, const char *subtraction_str,
                                const struct Elliptic_Curve *EC, struct Point *G)
{
    struct Point temp_point, point_to_subtract;
    mpz_t value;

    // Initialize points and value
    mpz_init(temp_point.x);
    mpz_init(temp_point.y);
    mpz_init(point_to_subtract.x);
    mpz_init(point_to_subtract.y);
    mpz_init_set_str(value, subtraction_str, 10);

    // Calculate G * subtraction_value
    Scalar_Multiplication(*G, &point_to_subtract, value);

    // Calculate -G * subtraction_value
    Point_Negation(&point_to_subtract, &temp_point);

    // Add to original point
    Point_Addition(point, &temp_point, &point_to_subtract);

    // Copy result back to input point
    mpz_set(point->x, point_to_subtract.x);
    mpz_set(point->y, point_to_subtract.y);

    // Cleanup
    mpz_clear(temp_point.x);
    mpz_clear(temp_point.y);
    mpz_clear(point_to_subtract.x);
    mpz_clear(point_to_subtract.y);
    mpz_clear(value);

    return true;
}

struct PreparedKeys prepare_keys(const char **input_pubkeys, int num_keys,
                                 int start_group, int end_group, int subtractions_per_group)
{
    struct PreparedKeys result;
    result.keys = malloc(num_keys * sizeof(struct PreparedKey));
    result.count = num_keys;

    // Initialize EC constants
    struct Elliptic_Curve EC;
    struct Point G;
    mpz_init_set_str(EC.p, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16);
    mpz_init_set_str(EC.n, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    mpz_init_set_str(G.x, "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16);
    mpz_init_set_str(G.y, "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16);

    for (int i = 0; i < num_keys; i++)
    {
        // Initialize the prepared key
        result.keys[i].pubkey_hex = malloc(67 * sizeof(char));
        result.keys[i].path = malloc(MAX_PATH_LENGTH * sizeof(char));
        result.keys[i].subtractions = malloc((end_group - start_group + 1) * subtractions_per_group * sizeof(uint64_t));
        result.keys[i].subtraction_count = 0;
        result.keys[i].valid = true;
        result.keys[i].path[0] = '\0'; // Initialize empty path

        // Initialize points
        mpz_init(result.keys[i].point.x);
        mpz_init(result.keys[i].point.y);

        // Parse input public key
        set_publickey((char *)input_pubkeys[i], &result.keys[i].point);

        // Process each group
        for (int group = start_group; group <= end_group && result.keys[i].valid; group++)
        {
            const char **current_group = NULL;

            // Select the appropriate group array
            switch (group)
            {
            case 33:
                current_group = group_33_values;
                break;
            case 32:
                current_group = group_32_values;
                break;
            case 31:
                current_group = group_31_values;
                break;
            case 30:
                current_group = group_30_values;
                break;
            case 29:
                current_group = group_29_values;
                break;
            case 28:
                current_group = group_28_values;
                break;
            case 27:
                current_group = group_27_values;
                break;
            case 26:
                current_group = group_26_values;
                break;
            case 25:
                current_group = group_25_values;
                break;
            case 24:
                current_group = group_24_values;
                break;
            case 23:
                current_group = group_23_values;
                break;
            case 22:
                current_group = group_22_values;
                break;
            case 21:
                current_group = group_21_values;
                break;
            case 20:
                current_group = group_20_values;
                break;
            case 19:
                current_group = group_19_values;
                break;
            case 18:
                current_group = group_18_values;
                break;
            case 17:
                current_group = group_17_values;
                break;
            case 16:
                current_group = group_16_values;
                break;
            case 15:
                current_group = group_15_values;
                break;
            case 14:
                current_group = group_14_values;
                break;
            case 13:
                current_group = group_13_values;
                break;
            case 12:
                current_group = group_12_values;
                break;
            case 11:
                current_group = group_11_values;
                break;
            case 10:
                current_group = group_10_values;
                break;
            case 9:
                current_group = group_9_values;
                break;
            case 8:
                current_group = group_8_values;
                break;
            case 7:
                current_group = group_7_values;
                break;
            case 6:
                current_group = group_6_values;
                break;
            case 5:
                current_group = group_5_values;
                break;
            case 4:
                current_group = group_4_values;
                break;
            case 3:
                current_group = group_3_values;
                break;
            case 2:
                current_group = group_2_values;
                break;
            case 1:
                current_group = group_1_values;
                break;
            }

            // Perform subtractions for this group
            for (int j = 0; j < subtractions_per_group && result.keys[i].valid; j++)
            {
                const char *subtraction = get_random_decimal(current_group, GROUP_SIZE);

                if (subtract_from_point(&result.keys[i].point, subtraction, &EC, &G))
                {
                    // Store subtraction value
                    result.keys[i].subtractions[result.keys[i].subtraction_count++] = strtoull(subtraction, NULL, 10);

                    // Update path
                    char temp[100];
                    snprintf(temp, sizeof(temp), "-%s,", subtraction);
                    strcat(result.keys[i].path, temp);
                }
                else
                {
                    result.keys[i].valid = false;
                    break;
                }
            }
        }

        // Generate hex representation of final point
        if (result.keys[i].valid)
        {
            generate_strpublickey(&result.keys[i].point, true, result.keys[i].pubkey_hex);
        }
    }

    // Cleanup EC constants
    mpz_clear(EC.p);
    mpz_clear(EC.n);
    mpz_clear(G.x);
    mpz_clear(G.y);

    return result;
}

uint64_t reverse_preparation_path(uint64_t final_privkey, const struct PreparedKey *prep_key)
{
    uint64_t original_privkey = final_privkey;

    // Add back all subtractions in reverse order
    for (int i = prep_key->subtraction_count - 1; i >= 0; i--)
    {
        original_privkey += prep_key->subtractions[i];
    }

    return original_privkey;
}

void cleanup_prepared_keys(struct PreparedKeys *keys)
{
    for (int i = 0; i < keys->count; i++)
    {
        free(keys->keys[i].pubkey_hex);
        free(keys->keys[i].path);
        free(keys->keys[i].subtractions);
        mpz_clear(keys->keys[i].point.x);
        mpz_clear(keys->keys[i].point.y);
    }
    free(keys->keys);
    keys->count = 0;
}
