"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const buffer_utils_1 = require("../buffer_utils");
const cbor_1 = require("../cbor");
/**
 * Exports the COSE Key as a raw key.
 *
 * It's effectively the same than:
 *
 * crypto.subtle.exportKey('raw', importedJWK)
 *
 * Note: This only works for KTY = EC.
 *
 * @param {Map<number, Uint8Array | number>} key - The COSE Key
 * @returns {Uint8Array} - The raw key
 */
const COSEKeyToRAW = (key) => {
    let decodedKey;
    if (key instanceof Uint8Array) {
        decodedKey = (0, cbor_1.cborDecode)(key);
    }
    else {
        decodedKey = key;
    }
    const kty = decodedKey.get(1);
    if (kty !== 2) {
        throw new Error(`Expected COSE Key type: EC2 (2), got: ${kty}`);
    }
    // its a private key
    if (decodedKey.has(-4)) {
        return decodedKey.get(-4);
    }
    return (0, buffer_utils_1.concat)(Uint8Array.from([0x04]), decodedKey.get(-2), decodedKey.get(-3));
};
exports.default = COSEKeyToRAW;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY29zZUtleS5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9jb3NlL2Nvc2VLZXkudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7QUFBQSxrREFBeUM7QUFDekMsa0NBQXFDO0FBRXJDOzs7Ozs7Ozs7OztHQVdHO0FBQ0gsTUFBTSxZQUFZLEdBQUcsQ0FDbkIsR0FBa0QsRUFDdEMsRUFBRTtJQUNkLElBQUksVUFBNEMsQ0FBQztJQUNqRCxJQUFJLEdBQUcsWUFBWSxVQUFVLEVBQUU7UUFDN0IsVUFBVSxHQUFHLElBQUEsaUJBQVUsRUFBQyxHQUFHLENBQUMsQ0FBQztLQUM5QjtTQUFNO1FBQ0wsVUFBVSxHQUFHLEdBQUcsQ0FBQztLQUNsQjtJQUNELE1BQU0sR0FBRyxHQUFHLFVBQVUsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUM7SUFDOUIsSUFBSSxHQUFHLEtBQUssQ0FBQyxFQUFFO1FBQ2IsTUFBTSxJQUFJLEtBQUssQ0FBQyx5Q0FBeUMsR0FBRyxFQUFFLENBQUMsQ0FBQztLQUNqRTtJQUVELG9CQUFvQjtJQUNwQixJQUFJLFVBQVUsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUMsRUFBRTtRQUN0QixPQUFPLFVBQVUsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQWUsQ0FBQztLQUN6QztJQUVELE9BQU8sSUFBQSxxQkFBTSxFQUNYLFVBQVUsQ0FBQyxJQUFJLENBQUMsQ0FBQyxJQUFJLENBQUMsQ0FBQyxFQUN2QixVQUFVLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxDQUFlLEVBQ2hDLFVBQVUsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQWUsQ0FDakMsQ0FBQztBQUNKLENBQUMsQ0FBQztBQUVGLGtCQUFlLFlBQVksQ0FBQyJ9