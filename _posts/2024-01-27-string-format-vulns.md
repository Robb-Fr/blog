---
title: "Exploiting string format vulnerabilities"
date: 2024-01-27
---

During a lab of Software Security class at EPFL, we came across this exercise on
which I pulled my hairs out.

## The problem

```c
// credits to https://hexhive.epfl.ch/
// compile with `gcc -static -O0 -m32 -s -Wl,--section-start=.text=0x11111111 2.c`
// note that -m32 is so addresses are short and --section-start is so there's no NULL in the address

#include <stdio.h>
#include <stdlib.h>

// this leaks memory but whatever, the program will exit quickly
char* read_flag(void) {
        FILE* f = fopen("flag", "r");
        char* flag = calloc(128, sizeof(char));
        fscanf(f, "%127s", flag);
        fclose(f);
        return flag;
}


char* flag;
int main() {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    setbuf(stdin, NULL);
    flag = read_flag();
    char input[128];
    int n = 42;

    printf("%d\n", n);
    printf("Hmmm look at this interesting pointer: %p\n", flag);
    printf("%d\n", n);
    fflush(stdout);    
    printf("Input your magical spell! ");
    scanf("%127[^\n]", input);
    printf(input);
    printf("\nHope you got what you wanted!\n");
    fflush(stdout);

    return 0;
}
```

Let us say this program is compiled and the executable runs on a server that we
can reach. Our goal is to display the content of the file `./flag`, and we can
observe that fortunately, this one is loaded in the variable `flag` (with
`flag=read_flag();`), but the content of this variable is not printed :(.

## Our attack surface

Getting back to the theory, we observe that this simple program does 2 things:
giving us the address of the pointer pointing to the beginning of the `flag`
char array, and then receives our input to print it immediately with `printf`
function.

Although we immediately observe that the usage of `printf` on unsanitised input
is insecure, exploiting it is another story, but we are off a great start.

## String format allows doing WHAT?

Understanding that string format printing with an improper function can lead to
vulnerabilities is fine. However, this does not, as is, allows to spawn a shell!
But they hide some tricky tricks in their implementation.

First, to get this, I extensively used this blog
[post](https://infosecwriteups.com/exploiting-format-string-vulnerability-97e3d588da1b)
that I really recommend reading for more details about what will follow.

What we will be interested in now is notably the `%p` format.

```c
a_pointer int*
printf("%p", a_pointer)
```

Prints the address of the pointer `a_pointer`, wherever it might be in memory
(e.g, `0x56550090`). To do so, `printf` basically follows the calling convention
of functions in C: when the `printf` function is called, it pushes the
parameters it will use and the return address on the stack (and eventually other
variables that we are not interested in today), and finally allocates space for
the local variables used by the function. This
[image](https://commons.wikimedia.org/wiki/File:Call_stack_layout.svg#/media/File:Call_stack_layout.svg)
from the Call stack Wikipedia page gives a good idea for this.

![`normal_printf`](/_posts//_2024-01-27-figures/normal_printf.jpg)

The image represents roughly what happens when the function is called. We see
that the stack stores 2 parameters for the `printf` function: a pointer to the
`"%p"` format string, and the example value of the `a_pointer` variable
(`0x56550090`). Roughly the `printf` algorithm reads the string pointed to by
the first parameter, and if it meets a special format specifier (such as `%p`),
it advances a pointer, represented by the green arrow, that gets the next
parameter and uses it as a replacement for the format specifier when printing.

What is interesting is what happens when we forget to put the right amount of parameters according to the desired format string.

```c
a_pointer int*
printf("%p")
```

In the code above, we do exactly this: the format string clearly seems to want a
pointer to be displayed, and this one should be the second parameter to
`printf`. This is the precise place where the function becomes unsecure: the
`printf` algorithm will still read whatever comes next on the stack and use it
as if it were the second parameter to `printf`.

![`bad_printf`](/_posts/_2024-01-27-figures/bad_printf.jpg)

The above picture represents what could happen. We now see how we could prepare
a special format string that will read on the stack until it can find something
interesting to show us.

## Cooking a payload and pwning

TODO