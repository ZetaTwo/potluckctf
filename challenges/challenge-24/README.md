# Traditional Feast: Nginx Spagetthi

## Category

Web

## Difficulty

4 meatballs (Should be hard but nobody really tried it, so I don't know)

## Description

Imagine a world where your code soars on the performance of nginx, dancing gracefully with modern scripting and transformation powers. While PHP aficionados are still trying to figure out their 500 internal errors and CGI fans are busy scripting their way to the last century, you'll be light-years ahead, sipping espresso and deploying functionalities like it's nobody's business.


## Flag

POTLUCK{concocted_cyber_casserole}

You can change it, the solution do not rely on the flag value.

## Deployment

- Build the docker image with the FLAG argument set to the flag value.
- expose port 80

## Solution

The challenge is a mix of XML injection/ prototype pollution and HTTP splitting/pipelineing. 

The main goal is to leak /flag on the download server, to do so you will need to exploit a CRLF injection in the /download proxy_pass to pipeline a request to /flag.
But you will need to also get a header injection in order to read the flag.

The first step is to find a way to inject XML. This can be done by escaping the CDATA directive in the recipe.
Then we can create a new `__proto__` tag with a name of `Accept-Charset` and a value that include the CRLF injection.


Sorry for the bad explanation, just look at the solve.py script.
