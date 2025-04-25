"use strict";
var __classPrivateFieldSet = (this && this.__classPrivateFieldSet) || function (receiver, state, value, kind, f) {
    if (kind === "m") throw new TypeError("Private method is not writable");
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a setter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot write private member to an object whose class did not declare it");
    return (kind === "a" ? f.call(receiver, value) : f ? f.value = value : state.set(receiver, value)), value;
};
var __classPrivateFieldGet = (this && this.__classPrivateFieldGet) || function (receiver, state, kind, f) {
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a getter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
    return kind === "m" ? f : kind === "a" ? f.call(receiver) : f ? f.value : state.get(receiver);
};
var _DataItem_data, _DataItem_buffer;
Object.defineProperty(exports, "__esModule", { value: true });
exports.DataItem = void 0;
const cbor_x_1 = require("cbor-x");
const _1 = require(".");
/**
 * DataItem is an extension defined https://www.rfc-editor.org/rfc/rfc8949.html#name-encoded-cbor-data-item
 *  > Sometimes it is beneficial to carry an embedded CBOR data item that is
 *  > not meant to be decoded immediately at the time the enclosing data item is being decoded.
 *
 * The idea of this class is to provide lazy encode and decode of cbor data.
 *
 * Due to a bug in the cbor-x library, we are eagerly encoding the data in the constructor.
 * https://github.com/kriszyp/cbor-x/issues/83
 *
 */
class DataItem {
    constructor(params) {
        _DataItem_data.set(this, void 0);
        _DataItem_buffer.set(this, void 0);
        if (!('data' in params) &&
            !('buffer' in params)) {
            throw new Error('DataItem must be initialized with either data or buffer');
        }
        if ('data' in params) {
            __classPrivateFieldSet(this, _DataItem_data, params.data, "f");
            // TODO: remove this once fixed in cbor-x
            // https://github.com/kriszyp/cbor-x/issues
            if (!('buffer' in params)) {
                __classPrivateFieldSet(this, _DataItem_buffer, (0, _1.cborEncode)(__classPrivateFieldGet(this, _DataItem_data, "f")), "f");
            }
        }
        if ('buffer' in params) {
            __classPrivateFieldSet(this, _DataItem_buffer, params.buffer, "f");
        }
    }
    get data() {
        if (!__classPrivateFieldGet(this, _DataItem_data, "f")) {
            __classPrivateFieldSet(this, _DataItem_data, (0, _1.cborDecode)(__classPrivateFieldGet(this, _DataItem_buffer, "f")), "f");
        }
        return __classPrivateFieldGet(this, _DataItem_data, "f");
    }
    get buffer() {
        if (!__classPrivateFieldGet(this, _DataItem_buffer, "f")) {
            __classPrivateFieldSet(this, _DataItem_buffer, (0, _1.cborEncode)(__classPrivateFieldGet(this, _DataItem_data, "f"), { useFloat32: 0 }), "f");
        }
        return __classPrivateFieldGet(this, _DataItem_buffer, "f");
    }
    static fromData(data) {
        return new DataItem({ data });
    }
}
exports.DataItem = DataItem;
_DataItem_data = new WeakMap(), _DataItem_buffer = new WeakMap();
(0, cbor_x_1.addExtension)({
    Class: DataItem,
    tag: 24,
    encode: (instance, encode) => {
        return encode(instance.buffer);
    },
    decode: (buffer) => {
        return new DataItem({ buffer });
    },
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiRGF0YUl0ZW0uanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi9zcmMvY2Jvci9EYXRhSXRlbS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7Ozs7Ozs7QUFBQSxtQ0FBc0M7QUFDdEMsd0JBQTJDO0FBTzNDOzs7Ozs7Ozs7O0dBVUc7QUFDSCxNQUFhLFFBQVE7SUFJbkIsWUFBWSxNQUF5QjtRQUhyQyxpQ0FBUztRQUNULG1DQUFvQjtRQUdsQixJQUNFLENBQUMsQ0FBQyxNQUFNLElBQUksTUFBTSxDQUFDO1lBQ25CLENBQUMsQ0FBQyxRQUFRLElBQUksTUFBTSxDQUFDLEVBQ3JCO1lBQ0EsTUFBTSxJQUFJLEtBQUssQ0FBQyx5REFBeUQsQ0FBQyxDQUFDO1NBQzVFO1FBQ0QsSUFBSSxNQUFNLElBQUksTUFBTSxFQUFFO1lBQ3BCLHVCQUFBLElBQUksa0JBQVMsTUFBTSxDQUFDLElBQUksTUFBQSxDQUFDO1lBRXpCLHlDQUF5QztZQUN6QywyQ0FBMkM7WUFDM0MsSUFBSSxDQUFDLENBQUMsUUFBUSxJQUFJLE1BQU0sQ0FBQyxFQUFFO2dCQUN6Qix1QkFBQSxJQUFJLG9CQUFXLElBQUEsYUFBVSxFQUFDLHVCQUFBLElBQUksc0JBQU0sQ0FBQyxNQUFBLENBQUM7YUFDdkM7U0FDRjtRQUVELElBQUksUUFBUSxJQUFJLE1BQU0sRUFBRTtZQUN0Qix1QkFBQSxJQUFJLG9CQUFXLE1BQU0sQ0FBQyxNQUFNLE1BQUEsQ0FBQztTQUM5QjtJQUNILENBQUM7SUFFRCxJQUFXLElBQUk7UUFDYixJQUFJLENBQUMsdUJBQUEsSUFBSSxzQkFBTSxFQUFFO1lBQ2YsdUJBQUEsSUFBSSxrQkFBUyxJQUFBLGFBQVUsRUFBQyx1QkFBQSxJQUFJLHdCQUFRLENBQU0sTUFBQSxDQUFDO1NBQzVDO1FBQ0QsT0FBTyx1QkFBQSxJQUFJLHNCQUFNLENBQUM7SUFDcEIsQ0FBQztJQUVELElBQVcsTUFBTTtRQUNmLElBQUksQ0FBQyx1QkFBQSxJQUFJLHdCQUFRLEVBQUU7WUFDakIsdUJBQUEsSUFBSSxvQkFBVyxJQUFBLGFBQVUsRUFBQyx1QkFBQSxJQUFJLHNCQUFNLEVBQUUsRUFBRSxVQUFVLEVBQUUsQ0FBQyxFQUFFLENBQUMsTUFBQSxDQUFDO1NBQzFEO1FBQ0QsT0FBTyx1QkFBQSxJQUFJLHdCQUFRLENBQUM7SUFDdEIsQ0FBQztJQUVNLE1BQU0sQ0FBQyxRQUFRLENBQUksSUFBTztRQUMvQixPQUFPLElBQUksUUFBUSxDQUFDLEVBQUUsSUFBSSxFQUFFLENBQUMsQ0FBQztJQUNoQyxDQUFDO0NBQ0Y7QUEzQ0QsNEJBMkNDOztBQUVELElBQUEscUJBQVksRUFBQztJQUNYLEtBQUssRUFBRSxRQUFRO0lBQ2YsR0FBRyxFQUFFLEVBQUU7SUFDUCxNQUFNLEVBQUUsQ0FBQyxRQUF1QixFQUFFLE1BQU0sRUFBRSxFQUFFO1FBQzFDLE9BQU8sTUFBTSxDQUFDLFFBQVEsQ0FBQyxNQUFNLENBQUMsQ0FBQztJQUNqQyxDQUFDO0lBQ0QsTUFBTSxFQUFFLENBQUMsTUFBa0IsRUFBVSxFQUFFO1FBQ3JDLE9BQU8sSUFBSSxRQUFRLENBQUMsRUFBRSxNQUFNLEVBQUUsQ0FBQyxDQUFDO0lBQ2xDLENBQUM7Q0FDRixDQUFDLENBQUMifQ==