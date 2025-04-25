"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.toUTF8 = exports.fromUTF8 = exports.areEqual = exports.concat = exports.decoder = exports.encoder = void 0;
exports.encoder = new TextEncoder();
exports.decoder = new TextDecoder();
function concat(...buffers) {
    const size = buffers.reduce((acc, { length }) => acc + length, 0);
    const buf = new Uint8Array(size);
    let i = 0;
    buffers.forEach((buffer) => {
        buf.set(buffer, i);
        i += buffer.length;
    });
    return buf;
}
exports.concat = concat;
function areEqual(buf1, buf2) {
    if (buf1 === buf2) {
        return true;
    }
    if (buf1.byteLength !== buf2.byteLength) {
        return false;
    }
    for (let i = 0; i < buf1.byteLength; i++) {
        if (buf1[i] !== buf2[i]) {
            return false;
        }
    }
    return true;
}
exports.areEqual = areEqual;
const fromUTF8 = (input) => exports.encoder.encode(input);
exports.fromUTF8 = fromUTF8;
const toUTF8 = (input) => exports.decoder.decode(input);
exports.toUTF8 = toUTF8;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYnVmZmVyX3V0aWxzLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vc3JjL2J1ZmZlcl91dGlscy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFBYSxRQUFBLE9BQU8sR0FBRyxJQUFJLFdBQVcsRUFBRSxDQUFDO0FBQzVCLFFBQUEsT0FBTyxHQUFHLElBQUksV0FBVyxFQUFFLENBQUM7QUFFekMsU0FBZ0IsTUFBTSxDQUFDLEdBQUcsT0FBcUI7SUFDN0MsTUFBTSxJQUFJLEdBQUcsT0FBTyxDQUFDLE1BQU0sQ0FBQyxDQUFDLEdBQUcsRUFBRSxFQUFFLE1BQU0sRUFBRSxFQUFFLEVBQUUsQ0FBQyxHQUFHLEdBQUcsTUFBTSxFQUFFLENBQUMsQ0FBQyxDQUFDO0lBQ2xFLE1BQU0sR0FBRyxHQUFHLElBQUksVUFBVSxDQUFDLElBQUksQ0FBQyxDQUFDO0lBQ2pDLElBQUksQ0FBQyxHQUFHLENBQUMsQ0FBQztJQUNWLE9BQU8sQ0FBQyxPQUFPLENBQUMsQ0FBQyxNQUFNLEVBQUUsRUFBRTtRQUN6QixHQUFHLENBQUMsR0FBRyxDQUFDLE1BQU0sRUFBRSxDQUFDLENBQUMsQ0FBQztRQUNuQixDQUFDLElBQUksTUFBTSxDQUFDLE1BQU0sQ0FBQztJQUNyQixDQUFDLENBQUMsQ0FBQztJQUNILE9BQU8sR0FBRyxDQUFDO0FBQ2IsQ0FBQztBQVRELHdCQVNDO0FBRUQsU0FBZ0IsUUFBUSxDQUFDLElBQWdCLEVBQUUsSUFBZ0I7SUFDekQsSUFBSSxJQUFJLEtBQUssSUFBSSxFQUFFO1FBQ2pCLE9BQU8sSUFBSSxDQUFDO0tBQ2I7SUFFRCxJQUFJLElBQUksQ0FBQyxVQUFVLEtBQUssSUFBSSxDQUFDLFVBQVUsRUFBRTtRQUN2QyxPQUFPLEtBQUssQ0FBQztLQUNkO0lBRUQsS0FBSyxJQUFJLENBQUMsR0FBRyxDQUFDLEVBQUUsQ0FBQyxHQUFHLElBQUksQ0FBQyxVQUFVLEVBQUUsQ0FBQyxFQUFFLEVBQUU7UUFDeEMsSUFBSSxJQUFJLENBQUMsQ0FBQyxDQUFDLEtBQUssSUFBSSxDQUFDLENBQUMsQ0FBQyxFQUFFO1lBQ3ZCLE9BQU8sS0FBSyxDQUFDO1NBQ2Q7S0FDRjtJQUVELE9BQU8sSUFBSSxDQUFDO0FBQ2QsQ0FBQztBQWhCRCw0QkFnQkM7QUFFTSxNQUFNLFFBQVEsR0FBRyxDQUFDLEtBQWEsRUFBYyxFQUFFLENBQUMsZUFBTyxDQUFDLE1BQU0sQ0FBQyxLQUFLLENBQUMsQ0FBQztBQUFoRSxRQUFBLFFBQVEsWUFBd0Q7QUFFdEUsTUFBTSxNQUFNLEdBQUcsQ0FBQyxLQUFpQixFQUFVLEVBQUUsQ0FBQyxlQUFPLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxDQUFDO0FBQTlELFFBQUEsTUFBTSxVQUF3RCJ9