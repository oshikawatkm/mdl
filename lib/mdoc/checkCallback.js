"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.onCatCheck = exports.buildCallback = exports.defaultCallback = void 0;
const debug_1 = __importDefault(require("debug"));
const errors_1 = require("./errors");
const log = (0, debug_1.default)('mdl');
exports.defaultCallback = ((verification) => {
    log(`Verification: ${verification.check} => ${verification.status}`);
    if (verification.status !== 'FAILED')
        return;
    throw new errors_1.MDLError(verification.reason ?? verification.check);
});
const buildCallback = (callback) => {
    if (typeof callback === 'undefined') {
        return exports.defaultCallback;
    }
    return (item) => {
        callback(item, exports.defaultCallback);
    };
};
exports.buildCallback = buildCallback;
const onCatCheck = (onCheck, category) => {
    return (item) => {
        onCheck({ ...item, category }, exports.defaultCallback);
    };
};
exports.onCatCheck = onCatCheck;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY2hlY2tDYWxsYmFjay5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9tZG9jL2NoZWNrQ2FsbGJhY2sudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7O0FBQUEsa0RBQTBCO0FBQzFCLHFDQUFvQztBQUVwQyxNQUFNLEdBQUcsR0FBRyxJQUFBLGVBQUssRUFBQyxLQUFLLENBQUMsQ0FBQztBQVlaLFFBQUEsZUFBZSxHQUF5QixDQUFDLENBQUMsWUFBWSxFQUFFLEVBQUU7SUFDckUsR0FBRyxDQUFDLGlCQUFpQixZQUFZLENBQUMsS0FBSyxPQUFPLFlBQVksQ0FBQyxNQUFNLEVBQUUsQ0FBQyxDQUFDO0lBQ3JFLElBQUksWUFBWSxDQUFDLE1BQU0sS0FBSyxRQUFRO1FBQUUsT0FBTztJQUM3QyxNQUFNLElBQUksaUJBQVEsQ0FBQyxZQUFZLENBQUMsTUFBTSxJQUFJLFlBQVksQ0FBQyxLQUFLLENBQUMsQ0FBQztBQUNoRSxDQUFDLENBQUMsQ0FBQztBQUVJLE1BQU0sYUFBYSxHQUFHLENBQUMsUUFBMEMsRUFBd0IsRUFBRTtJQUNoRyxJQUFJLE9BQU8sUUFBUSxLQUFLLFdBQVcsRUFBRTtRQUFFLE9BQU8sdUJBQWUsQ0FBQztLQUFFO0lBQ2hFLE9BQU8sQ0FBQyxJQUE0QixFQUFFLEVBQUU7UUFDdEMsUUFBUSxDQUFDLElBQUksRUFBRSx1QkFBZSxDQUFDLENBQUM7SUFDbEMsQ0FBQyxDQUFDO0FBQ0osQ0FBQyxDQUFDO0FBTFcsUUFBQSxhQUFhLGlCQUt4QjtBQUVLLE1BQU0sVUFBVSxHQUFHLENBQUMsT0FBd0MsRUFBRSxRQUE0QyxFQUFFLEVBQUU7SUFDbkgsT0FBTyxDQUFDLElBQThDLEVBQUUsRUFBRTtRQUN4RCxPQUFPLENBQUMsRUFBRSxHQUFHLElBQUksRUFBRSxRQUFRLEVBQUUsRUFBRSx1QkFBZSxDQUFDLENBQUM7SUFDbEQsQ0FBQyxDQUFDO0FBQ0osQ0FBQyxDQUFDO0FBSlcsUUFBQSxVQUFVLGNBSXJCIn0=