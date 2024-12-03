import sha256 from "sha256";

const genSha256 = (message: string): string => sha256(message);

export default genSha256;
