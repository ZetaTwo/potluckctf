#include "../../kernel/interface.h"
#include "../../kernel/helper.h"
#include "elk/elk.h"


// Fixes to make the rest compile

int  errno;

int isspace(int c) {
    return c == ' ' || (unsigned)c-'\t' < 5;
}

int isdigit(int c) {
    return (unsigned)c-'0' < 10;
}

void __assert_fail() {}


/*
 * Copyright (C) 1993 by Sun Microsystems, Inc. All rights reserved.
 * Open Source
*/
#include "modf.c"


/*
 * Copyright (c) 1988-1993 The Regents of the University of California.
 * Copyright (c) 1994 Sun Microsystems, Inc.
 * Open Source
*/
#include "strtod.c"


// Only now actual js driver code begins


// Print arg[0]
static jsval_t js_print(struct js *js, jsval_t *args, int nargs) {
    if(js_type(args[0]) == JS_STR) {
        size_t len;
        char * str = js_getstr(js, args[0], &len);
        for(size_t i=0;i<len;i++) {
            sys_putchar(str[i]);
        }
    }else {
        sys_puts((char *)js_str(js, args[0]));
    }
    return js_mkundef();
}

// Prints all arguments, one by one, delimit by space on serial
static jsval_t js_serial(struct js *js, jsval_t *args, int nargs) {
    for (int i = 0; i < nargs; i++) {
        if(i != 0) {
            sys_putchar_serial(' ');
        }
        sys_puts_serial((char *)js_str(js, args[i]));
    }
    sys_putchar_serial('\n');  // Finish by newline
    return js_mkundef();
}

volatile uint16_t* SCREEN = (volatile uint16_t*)0xb8000; //  Text screen video memory for color monitors 
static jsval_t js_writechar(struct js *js, jsval_t *args, int nargs) {
    int location = (js_getnum(args[0]));
    char c = (js_getnum(args[1]));
    SCREEN[location] = (0x0700 | c);
    return js_mkundef();
}

static jsval_t js_setposition(struct js *js, jsval_t *args, int nargs) {
    uint32_t* screenIndex = sys_screen_index_ptr();
    int location = (js_getnum(args[0]));
    *screenIndex = location;
    
    // reset screen if set to 0
    if(location == 0) {
        for(int i=0;i<80*60;i++) {
            SCREEN[i] = 0x0720;
        }
    }
    
    return js_mknum(*screenIndex);
}
static jsval_t js_getposition(struct js *js, jsval_t *args, int nargs) {
    uint32_t* screenIndex = sys_screen_index_ptr();
    return js_mknum(*screenIndex);
}


const int ACTION_EXIT = 0;
const int ACTION_START = 1;
const int ACTION_KEY  = 2;

char nextJSPath[64];
char vmPath[64];
const int ACTION_JS = 3;

int nextAction = ACTION_EXIT;

char last_pressed_key = 0;

static jsval_t js_key(struct js *js, jsval_t *args, int nargs) {
    return js_mknum(last_pressed_key);
}

static jsval_t js_keydown(struct js *js, jsval_t *args, int nargs) {
    sys_puts_serial((char *)js_str(js, args[0]));
    return js_mkundef();
}


static jsval_t js_expectKey(struct js *js, jsval_t *args, int nargs) {
    nextAction = ACTION_KEY;
    return js_mkundef();
}

static jsval_t js_expectJS(struct js *js, jsval_t *args, int nargs) {
    if(js_type(args[0]) == JS_STR) {
        size_t len;
        char * str = js_getstr(js, args[0], &len);
        for(size_t i=0;i<len && i<(sizeof(nextJSPath)-1);i++) {
            nextJSPath[i] = str[i];
        }
        nextJSPath[len] = 0;
        nextAction = ACTION_JS;
    }
    return js_mkundef();
}

static void* convertArgument(struct js *js, jsval_t arg) {
    if(js_type(arg) == JS_STR) {
        size_t len;
        return (void*)js_getstr(js, arg, &len);
    }else if(js_type(arg) == JS_NUM) {
        return (void*)((int)js_getnum(arg));
    }else if(js_type(arg) == JS_TRUE) {
        return (void*)(1);
    }else if(js_type(arg) == JS_FALSE) {
        return (void*)(0);
    }else{
        return NULL;
    }
}

static jsval_t js_runVM(struct js *js, jsval_t *args, int nargs) {
    if(js_type(args[0]) == JS_STR && nargs >= 1) {
        size_t len;
        char * str = js_getstr(js, args[0], &len);
        for(size_t i=0;i<len && i<(sizeof(vmPath)-1);i++) {
            vmPath[i] = str[i];
        }
        vmPath[len] = 0;
        
        int lenFile = sys_read_file(vmPath, (uint8_t*)TMP_FILE2, TMP_FILE2_SIZE);
        ((uint8_t*)TMP_FILE2)[lenFile] = 0;
        
        void* arg0 = NULL;
        if(nargs >= 2) {
            arg0 = convertArgument(js, args[1]);
        }
        void* arg1 = NULL;
        if(nargs >= 3) {
            arg1 = convertArgument(js, args[2]);
        }
        void* arg2 = NULL;
        if(nargs >= 4) {
            arg2 = convertArgument(js, args[3]);
        }
        void* arg3 = NULL;
        if(nargs >= 5) {
            arg3 = convertArgument(js, args[4]);
        }
        
        //char buf[128];
        
        //snprintf(buf, sizeof(buf), "JS_DRIVER RUN VM: %p %p %p %p\n", arg0, arg1, arg2, arg3);
        //sys_puts_serial(buf);
        int code = (int)sys_execute_vm(((uint8_t*)TMP_FILE2), arg0, arg1, arg2, arg3);
        //snprintf(buf, sizeof(buf), "JS_DRIVER RUN VM DONE: %p %p %p %p\n", arg0, arg1, arg2, arg3);
        //sys_puts_serial(buf);
        return js_mknum(code);
    }
    return js_mkundef();
}

static jsval_t js_toString(struct js *js, jsval_t *args, int nargs) {
    if(js_type(args[0]) == JS_STR) {
        return args[0];
    }else if(js_type(args[0]) == JS_NUM) {
        unsigned char buf[] = {0, 0};
        buf[0] = ((unsigned char)js_getnum(args[0]));
        return js_mkstr(js, buf ,1);
    }
    return js_mkundef();
}

static jsval_t js_toHex(struct js *js, jsval_t *args, int nargs) {
    if(js_type(args[0]) == JS_NUM) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%02x", ((unsigned char)js_getnum(args[0])));
        return js_mkstr(js, buf , 2);
    }
    return js_mkundef();
}

static jsval_t js_array_length(struct js *js, jsval_t *args, int nargs) {
    if(js_chkargs(args, nargs, "j"));
    jsval_t global = js_glob(js);
    js_set(js, global, "__a", args[0]); 
    return js_eval(js, "__a.length", ~0);
}

static jsval_t js_array_get(struct js *js, jsval_t *args, int nargs) {
    if(js_chkargs(args, nargs, "jd"));
    jsval_t global = js_glob(js);
    js_set(js, global, "__a", args[0]); 
    
    char line[64];
    snprintf(line, sizeof(line), "__a.d_%d", (int)js_getnum(args[1]));
    return js_eval(js, line, ~0);
}

static jsval_t js_array_set(struct js *js, jsval_t *args, int nargs) {
    if(js_chkargs(args, nargs, "jdj"));
    char line[64];
    snprintf(line, sizeof(line), "d_%d", (int)js_getnum(args[1]));
    js_set(js, args[0], line, args[2]);
    return js_mkundef();
}

static jsval_t js_array_add(struct js *js, jsval_t *args, int nargs) {
    if(js_chkargs(args, nargs, "jj"));
    jsval_t global = js_glob(js);
    js_set(js, global, "__a", args[0]); 
    
    jsval_t alen = js_array_length(js, args, 1);
    double alenv = 0;
    if(js_type(alen) != JS_UNDEF) {
        alenv = js_getnum(alen);
    }
    
    js_set(js, args[0], "length", js_mknum(alenv+1));
    jsval_t argsCall[] = {args[0], js_mknum(alenv), args[1]};
    return js_array_set(js, argsCall, 3);
}

static jsval_t js_toArray(struct js *js, jsval_t *args, int nargs) {
    if(js_type(args[0]) == JS_STR) {
        jsval_t lst = js_mkobj(js);
        
        size_t len;
        char* str =  js_getstr(js, args[0], &len);
        
        for(size_t i=0;i<len;i++) {
            jsval_t argsCall[] = {lst, js_mknum(str[i]&0xff)};
            js_array_add(js, argsCall, 2);
        }
        
        return lst;
    }
    return js_mkundef();
}


struct js *global_js;

void resetJS() {
    global_js = js_create((char*)DRIVER_JS_STRUCT, DRIVER_JS_STRUCT_SIZE);
    jsval_t res = js_mkundef();


    jsval_t global = js_glob(global_js);
    jsval_t screen = js_mkobj(global_js);
    
    // PRINT API
    
    js_set(global_js, global, "p", js_mkfun(js_print));
    js_set(global_js, global, "sr", js_mkfun(js_serial));
    
    // OS API
    
    js_set(global_js, global, "ek", js_mkfun(js_expectKey));
    js_set(global_js, global, "ejs", js_mkfun(js_expectJS));
    js_set(global_js, global, "rvm", js_mkfun(js_runVM));
    js_set(global_js, global, "ts", js_mkfun(js_toString));
    js_set(global_js, global, "ta", js_mkfun(js_toArray));
    js_set(global_js, global, "th", js_mkfun(js_toHex));
    
    // ARRAY API
    
    js_set(global_js, global, "al", js_mkfun(js_array_length));
    js_set(global_js, global, "ag", js_mkfun(js_array_get));
    js_set(global_js, global, "as", js_mkfun(js_array_set));
    js_set(global_js, global, "aa", js_mkfun(js_array_add));
    
    // SCREEN API
    
    js_set(global_js, global, "s", screen); 
    js_set(global_js, screen, "w", js_mkfun(js_writechar));
    js_set(global_js, screen, "s", js_mkfun(js_setposition));
    js_set(global_js, screen, "g", js_mkfun(js_getposition));
    js_set(global_js, screen, "k", js_mkfun(js_key));
    js_set(global_js, screen, "kd", js_mkfun(js_keydown));
}


uint32_t runJS(char* jsString) {
    
    jsval_t res;
    nextAction = ACTION_START;
    
    //sys_puts_serial("JS_DRIVER STARTING PROGRAM\n");
    
    while(nextAction != ACTION_EXIT) {
        
        int curAction = nextAction;
        nextAction = ACTION_EXIT;
        
        if(curAction == ACTION_START) {
            resetJS();
            res = js_eval(global_js, jsString, ~0U);
            
        }else if(curAction == ACTION_KEY) {
            last_pressed_key = sys_wait_for_key();
            res = js_eval(global_js, "s.kd();", ~0);
        }else if(curAction == ACTION_JS) {
            resetJS();
            int len = sys_read_file(nextJSPath, (uint8_t*)TMP_FILE, TMP_FILE_SIZE);
            ((uint8_t*)TMP_FILE)[len] = 0;
            
            // Decrypt js file
            sys_read_file(RC4_PATH, (uint8_t*)TMP_FILE2, TMP_FILE2_SIZE);
            sys_execute_vm((uint8_t*)TMP_FILE2, 0, (char*)TMP_FILE, (void*)len, 0);
            
            res = js_eval(global_js, (uint8_t*)TMP_FILE, ~0U);
        }
        /*
        // cast res to number or print error etc.
        sys_puts_serial("JS_DRIVER: ");
        sys_puts_serial((char*)js_str(global_js, res));
        sys_putchar_serial('\n');
        
        if(nextAction == ACTION_EXIT) {
            sys_puts_serial("JS_DRIVER NEXT EXIT\n");
        }else if(nextAction == ACTION_START) {
            sys_puts_serial("JS_DRIVER NEXT START\n");
        }else if(nextAction == ACTION_KEY) {
            sys_puts_serial("JS_DRIVER NEXT KEY\n");
        }else if(nextAction == ACTION_JS) {
            sys_puts_serial("JS_DRIVER NEXT JS '");
            sys_puts_serial(nextJSPath);
            sys_puts_serial("'\n");
        }
        */
        
        
    }
        

    return 0;
}

void entrypoint() {
    //sys_puts_serial("Loaded JS Driver\n");
    reg_sys(SYSCALL_EXECUTE_JS, runJS);
}