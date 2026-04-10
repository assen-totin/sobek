# Sobek

_O my heart of different ages! Do not stand up as a witness against me, do not be opposed to me in the tribunal, do not be hostile to me in the presence of the keeper of the balance._

## RAISON D’ÊTRE

The boom of "artificial intelligence" systems (in reality, large language models without anything even close to an intellect) has led to a boom of data scraping from the Internet. The latter presents a challenge to web sites for a number of reasons:
In pursuit of quick investors' money, these systems tend to not respect the "robots.txt" restrictions.
For the same reason, they try to gather as much data as possible in the least time possible, leading to huge spikes of load on the web servers, akin to a DoS attack.

Unlike decent ones, such AI crawlers try to hide their presence by using large pools of IP addresses (which makes IP-address blocking impossible), and/or by masking themselves as regular browsers (which makes filtering by the User-Agent string impossible) etc.

The effect is exacerbated by suboptimal composition of many web sites, e.g. sites not using in-memory cache for sessions, not using in-memory cache for ORM, not using CDN for images, translating the load of the web servers into a heavy load for the database and the storage.

## HOW TO BLOCK UNWANTED CRAWLERS

Unwanted web clients may be deterred by imposing the requirement for the client to do some small amount of computational work prior to granting it access to the requested resource (i.e. to respond to a challenge presented by the server). This is not a new concept and it has been outlined as back as 1997 by Adam Back in his HashCash proposal: http://www.hashcash.org/papers/hashcash.pdf 

There are two ways the challenge will stop crawlers:

- They are unlikely to run JavaScript code, hence the page with the challenge will look to them as an empty page without links - a dead end halting the crawl.
- Even if they run the JavaScript code and pass the challenge, they are unlikely to save and use cookies (e.g., Google Bot uses real Chromium instances to render the page, but cannot use cookies, because each page is loaded by an independent, ephemeral Chromium instance).

## WHY NOT JUST USE GOOGLE’S RE-CAPTCHA?

For a number of reasons:
- Re-CAPTCHA is a proprietary product that nobody knows how it works.
- It may stop working at any time, Google willing so.
- Google may be incentivised to exclude certain "friendly" (read: paying) crawlers from the scope of the CAPTCHA, giving them a carte-blanche.
- The latter surely applies to Google's own AI crawlers.
- It may cost much more money than expected to run re-CAPTCHA, especially with the increased load from AI crawlers (it is paid by the volume of requests is checks).

## SOBEK'S WORKFLOW

The workflow is as follows:

- A web client opens www.example.com and reaches the HAProxy in front of it.
- HAProxy checks the presence of the Sobek cookie. If it exists, the request is forwarded to the appropriate backend for www.example.com 
- If the Sobek cookie is missing, HAProxy forwards the request to the Sobek backend (the Nginx module) instead
- The Sobek backend responds with some simple JavaScript code. It may, optionally, include a "Please wait" (or "Verifying you are not a robot") page, or just keep the page blank while the challenge is being processed by the web client
- The web client runs the JavaScript code, which makes an AJAX GET request to /sobek on the same domain to fetch a challenge; HAProxy ensures requests to /sobek are always routed to the Sobek Nginx module
- Sobek backend generates a challenge, adds the current timestamp and signes them with its key, then sends this data back to the web client
- The web client solves the challenge, then makes a POST AJAX request to /sobek to submit the solution together with the original challenge, its timestamp and signature
- The Sobek backend verifies that the challenge is not too old, that its signature is correct and that the challenge has been properly solved; if so, it returns its cookie (valid for certain amount of time) to the web client
- The JavaScript code on the web client sets the Sobek cookie for the domain it was loaded from and reloads the location (which still holds the original destination); the request now includes the Sobek cookie and gets routed by HAProxy to the proper backend.

## THE CHALLENGE

The challenge is composed with such requirements so that solving it is an indirect proof of human presence:

- JavaScript is required, which a browser will always have, but bots may not support.
- The challenge uses the browser’s native crypto API, which only a real browser has; scripts or simple URL loading tools do not have it, and neither does NodeJS.
- Using cookies ensures that the same browser must be reused on each page of the web site - which is what a legitimate user will do, but the crawler is unlikely to.

The challenge composition is as follows:

- The challenge is composed by Sobek backend from random data (at least 64 bytes, since the client will need to compute its 256-bit hash as a solution) and send to the web client.
- The web client computes the SHA-256 hash from the challenge, starting with a zero as a salt. It checks if the first N bits of the hash (as defined in the challenge) are all zeroes; if not, the salt is incremented by one and the computation is repeated (which, on average, will require 2^N/2 computations). Modern client hardware should be able to produce 10-100 K hashes per second, so the complexity of the challenge should be set to a value that will not take more than a second or so to solve.
- When ready, the web client submits the last salt it used as a solution, together with the original challenge.
- The Sobek backend computes the hash from the challenge with the solution it has received as a salt and verifies that its first N bits are indeed zeroes. The original challenge, timestamp and signature ensure that the challenge cannot be tampered with or, once solved, passed to other web clients.

Thus, the Sobek backend only needs to compute two digital signatures and one hash per challenge, which makes the load on it negligible.

## THE SOBEK COOKIE

The Sobek cookie has some reasonable validity in order to avoid too frequent checks, e.g. one week to one month.

The cookie is set on behalf of the domain that is being visited, so it is both a first-party cookie and is also essential for allowing access to the requested web resource (akin to a login cookie), hence there is no need to obtain user’s consent about it (no cookie banner required under GDPR).

The cookie is digitally signed by the Sobek backend. In order to ensure that the client side cannot forge a cookie to bypass the verification, before accepting it, HAProxy decodes it and performs the following checks:

- Verfies the signature using the same key as the Sobek backend.
- Verifies the timestamp in the cookie payload is not too old.

HAProxy cannot onitsown process the cookie in the described way, but it has a Lua interpreter built-in that can easily achieve this.

## FURTHER CONSIDERATIONS

### Solution Complexity

It may well be seen that the challenge complexity is not really vital to the outcome; since we need binary output ("able to solve it" or "not able to do so"), it does not really matter how many bits of certan value (zeroes, in our case) the client should seek (at the beginning of the hash, in our case); therefore, in order so make this less obtrusive to web slower clients, requesting one zero byte instead of two would shrink the average number of expected hash computations by the web client from 32,768 to just 128.

When chosing this complexity of the solution required, it should also be well undestood that 2^N/2 is the statistic _average_ number of runs to find it; while the client might be extremely lucky and find it on the very first run, it might also be extremely unlucky and run for much longer than the average; the theoretical upper limit for a 256-bit hash would be in the order of 2^256 runs; however, such prolonged runs are quite rare.

### HAProxy

Some well-known URL should likely be exempted from the check for the Sobek cookie in HAProxy, like:

- `/robots.txt`
- `/favicon.ico`
- `/.well-known/` and everything beneath it.

Some well-known User-Agent strings may be exempted from the challenge, e.g., the Google Bot. It should be noted that such whitelisting has to be done carefully, as there will be nothing to stop an offensive bot that hides under the User-Agent string of a whitelisted one.

As an alternative, some well-known IP address ranges may be whitelisted (for example, those used by the Google Bot are usually in the `66.249.64.0/20` range). Of course, any other bot that somehow comes from these addresses will have unrestricted access too.

## IMPLEMENTATION

The server side is implemented as an Nginx module. This ensures fastest possible performance, combined with the scalability of its multi-threading to keep the system responsive even in the case of influx of requests from a scraping bot. The computation of hashes will is offloaded to the OS-provided standard cryptographic library from the OpenSSL suite, `libcrypto`. There are no database connections or other external systems involved to ensure the fastest possible performance and to remove dependency on external systems. 

The client side is implemented as static content, served by the Nginx module via a default handler for non-existing content. The computations on the client side are done in JavaScript using the native browser-provided crypto API; this minimises the amount of code the server needs to feed to the client (zero bytes for hash computation compared to several dozens of KB of code when using a JavaScript implementation of hashing). For the same reason, the client side pulls the challenge and pushes the solution using the native browser-provided AJAX methods without the use of third-party tools; thus the whole client side is less than 100 lines of code.

The verification of the login cookie signature on the HAProxy is implemented as a Lua script that HAProxy can run natively inside itself. It is not included in this repository.

## WHO IS SOBEK?

In Egyptian mythology, Sobek is the crocodile deity that takes part in the Weighing of Heart ceremony that each deceased person is subjected to; his role is to consume the ones that are found to have a heavy heart, preventing them from reaching the afterlife.

## NEED HELP FOR A COMPLETE SOLUTION?

Contact me at assen.totin@gmail.com for a complete, web based, solution that manages your TLS offloading at scale, renews your certificates, secures access with 2FA for public systems that lack it and protects them from the influx of web bots.

