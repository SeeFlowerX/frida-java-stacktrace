import { getFramesInfo } from "./lib";

function log(msg: string) {
    console.log(`${msg}`);
}

function main() {
    log(`hello frida-java-stacktrace`);

    Java.perform(() => {
        Java.use('java.io.File').$init.overload('java.lang.String').implementation = function(){
            let [file] = arguments;
            let frames = getFramesInfo();
            log(`[File.$init] file => ${file}\nStackTrace:\n\t${frames.getStackTraceString()}`);
            return this.$init.apply(this, arguments);
        }
    });
}

setImmediate(main)

// frida -UF -l _agent.js -o tmp.log