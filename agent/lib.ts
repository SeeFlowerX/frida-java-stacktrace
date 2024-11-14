import { getApi, withRunnableArtThread, ArtStackVisitor, translateMethod } from 'frida-java-bridge/lib/android'

const translateLocation = new NativeFunction(
    Module.getExportByName('libart.so', '_ZN3art7Monitor17TranslateLocationEPNS_9ArtMethodEjPPKcPi'),
    'void',
    [
        'pointer',
        'uint32',
        'pointer',
        'pointer',
    ],
    {
        exceptions: 'propagate'
    });

export interface FrameInfo {
    'class': string;
    fileName: string | null;
    lineNumber: number;
    fullSignature: string
    source: string;
}

class FramesInfo extends Array<FrameInfo> {

    getStackTraceString(): string {
        if (this.length == 0) {
            return "null";
        }
        let infos = this.map((frame: FrameInfo) => {
            return `${frame.fullSignature}->[${frame.fileName}:${frame.lineNumber}]`
        })
        return infos.join("\n\t");
    }

}

class DebugStackVisitor extends ArtStackVisitor {
    frames: FramesInfo;

    constructor(thread: any) {
        super(thread, getApi()['art::Thread::GetLongJumpContext'](thread), 'include-inlined-frames');
        this.frames = new FramesInfo();
    }

    visitFrame() {
        this._collectFrame(this.describeLocation());
        return true;
    }

    _collectFrame(location: string) {
        if (location === 'upcall')
            return;

        const tokens = location.split('\'', 3);
        const rawMethodSignature = tokens[1];
        if (rawMethodSignature.startsWith('<'))
            return;
        const details = tokens[2];

        const separatorIndex = rawMethodSignature.indexOf(' ');
        const returnType = rawMethodSignature.substring(0, separatorIndex);
        const rest = rawMethodSignature.substring(separatorIndex + 1);
        const argsStartIndex = rest.indexOf('(');
        const argsEndIndex = rest.indexOf(')', argsStartIndex + 1);
        const argTypes = rest.substring(argsStartIndex + 1, argsEndIndex);

        const classAndMethodName = rest.substring(0, argsStartIndex);
        const methodNameStartIndex = classAndMethodName.lastIndexOf('.');
        const className = classAndMethodName.substring(0, methodNameStartIndex);
        const methodName = classAndMethodName.substring(methodNameStartIndex + 1);
        let dexPc = parseInt(details.substring(13), 16);

        const fullSignature = `${returnType} ${className}.${methodName}(${argTypes})`;

        const actualMethod = this.getMethod();
        if (actualMethod == null) return;
        const translatedMethod = translateMethod(actualMethod);
        if (!translatedMethod.equals(actualMethod)) {
            dexPc = 0;
        }
        const fileNamePtr = Memory.alloc(16);
        const lineNumberPtr = fileNamePtr.add(8);
        translateLocation(translatedMethod, dexPc, fileNamePtr, lineNumberPtr);
        const fileName = fileNamePtr.readPointer().readUtf8String();
        const lineNumber = lineNumberPtr.readS32();

        this.frames.push({
            'class': className,
            fileName,
            lineNumber,
            fullSignature,
            source: 'dynamic'
        });
    }
}

export function getFramesInfo() {
    let frames = new FramesInfo();

    const vm = Java.vm;
    withRunnableArtThread(vm, vm.getEnv(), thread => {
        const visitor = new DebugStackVisitor(thread);
        visitor.walkStack(true);
        frames = visitor.frames;
    });

    return frames;
}