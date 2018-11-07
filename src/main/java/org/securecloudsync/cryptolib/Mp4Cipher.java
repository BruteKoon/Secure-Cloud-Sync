package org.securecloudsync.cryptolib;

import com.sun.istack.internal.NotNull;

import java.io.*;

import static org.securecloudsync.filesystem.CleanPath.cleanString;
import static org.securecloudsync.ui.controllers.PopupController.wrongPopup;

/**
 * mp4파일 부분 암호화를 수행하는 클레스
 */
public class Mp4Cipher {
    private final static int BUFSIZE = 67108864 * 2;

    /**
     * @param file 암호화 할 파일 이름
     * @throws Exception
     */
    public static void encrypt(String file, String localPath, String securePath) throws Exception {
        String psrc = localPath + "\\" + file;
        String pdes = securePath + "\\" + file + ".SCS";
        String src = cleanString(psrc);
        String des = cleanString(pdes);

        if (src == "false" || des == "false") {
            wrongPopup("wrong file Path");
        } else {
            byte[] iv = KeyManagement.geniv();
            byte[] key = KeyManagement.genKey();

            RandomAccessFile in = new RandomAccessFile(src, "r");
            OutputStream out = new FileOutputStream(des);

            Crypto.encrypt(key, iv, out, securePath);
            byte[] buffer = new byte[BUFSIZE];
            int mdatOffset = 0;

            int offset = 0;
            int frameSize = 0;

            byte[] size = new byte[4];
            int read = in.read(buffer);
            int leaveSize = read;
            //find mdat offset
            while (true) {
                mdatOffset++;
                if (buffer[mdatOffset] == 0x6d) { //m
                    if (buffer[mdatOffset + 1] == 0x64 && buffer[mdatOffset + 2] == 0x61 && buffer[mdatOffset + 3] == 0x74) {
                        System.arraycopy(buffer, mdatOffset - 4, size, 0, 4);

                        offset = mdatOffset;
                        break;
                    } else if (buffer[mdatOffset + 1] == 0x6f && buffer[mdatOffset + 2] == 0x6f && buffer[mdatOffset + 3] == 0x76) {
                        System.arraycopy(buffer, mdatOffset - 4, size, 0, 4);
                        mdatOffset += hexToDec(size);
                    }
                }
            }
            //find frame
            while (true) {
                while (true) {
                    if (offset > read - 7) {
                        break;
                    }
                    if (buffer[offset] == 0x65) {
                        if (buffer[offset + 1] + 0x100 == 0x88) {
                            byte test = (byte) (buffer[offset + 2] >> 4);
                            if (test + 16 == 0x8) {
                                System.arraycopy(buffer, offset - 4, size, 0, 4);
                                frameSize = hexToDec(size);
                                if (frameSize <= 0) {
                                    offset++;
                                } else if (frameSize > 0xffffff) {
                                    offset++;
                                } else if (offset + frameSize <= leaveSize) {
                                    byte[] target = new byte[frameSize];
                                    System.arraycopy(buffer, offset + 3, target, 0, frameSize - 3);
                                    byte[] encrypt = Crypto.encrypt(target, key, iv);
                                    System.arraycopy(encrypt, 0, buffer, offset + 3, frameSize - 3);
                                    offset += frameSize;
                                } else {
                                    break;
                                }
                            } else
                                offset++;
                        } else {
                            offset++;
                        }
                    } else if (buffer[offset] == 0x41) {
                        if (buffer[offset + 1] + 0x100 == 0x9a || buffer[offset + 1] + 0x100 == 0x9b) {
                            System.arraycopy(buffer, offset - 4, size, 0, 4);
                            frameSize = hexToDec(size);
                            if (frameSize <= 0) {
                                offset++;
                            } else if (frameSize > 0xfffff) {
                                offset++;
                            } else if (offset + frameSize <= leaveSize) {
                                byte[] target = new byte[frameSize];
                                System.arraycopy(buffer, offset + 3, target, 0, frameSize - 3);
                                byte[] encrypt = Crypto.encrypt(target, key, iv);
                                System.arraycopy(encrypt, 0, buffer, offset + 3, frameSize - 3);
                                offset += frameSize;
                            } else {
                                break;
                            }
                        } else if (buffer[offset + 1] + 0x100 == 0x9e || buffer[offset + 1] + 0x100 == 0x9f) {
                            System.arraycopy(buffer, offset - 4, size, 0, 4);
                            frameSize = hexToDec(size);
                            if (frameSize <= 0) {
                                offset++;
                            } else if (frameSize > 0xfffff) {
                                offset++;
                            } else if (offset + frameSize <= leaveSize) {
                                offset += frameSize;
                            } else {
                                break;
                            }
                        } else
                            offset++;
                    } else if (buffer[offset] + 0x100 == 0x61) {
                        if (buffer[offset + 1] + 0x100 == 0x9a || buffer[offset + 1] + 0x100 == 0x9b) {
                            System.arraycopy(buffer, offset - 4, size, 0, 4);
                            frameSize = hexToDec(size);
                            if (frameSize <= 0) {
                                offset++;
                            } else if (frameSize > 0xfffff) {
                                offset++;
                            } else if (offset + frameSize <= leaveSize) {
                                byte[] target = new byte[frameSize];
                                System.arraycopy(buffer, offset + 3, target, 0, frameSize - 3);
                                byte[] encrypt = Crypto.encrypt(target, key, iv);
                                System.arraycopy(encrypt, 0, buffer, offset + 3, frameSize - 3);
                                offset += frameSize;
                            } else {
                                break;
                            }
                        } else if (buffer[offset + 1] + 0x100 == 0x9e || buffer[offset + 1] + 0x100 == 0x9f) {
                            System.arraycopy(buffer, offset - 4, size, 0, 4);
                            frameSize = hexToDec(size);
                            if (frameSize <= 0) {
                                offset++;
                            } else if (frameSize > 0xfffff) {
                                offset++;
                            } else if (offset + frameSize <= leaveSize) {
                                offset += frameSize;
                            } else {
                                break;
                            }
                        } else
                            offset++;
                    } else if (buffer[offset] == 0x01) {
                        if (buffer[offset + 1] + 0x100 == 0x9e || buffer[offset + 1] + 0x100 == 0x9f) {
                            System.arraycopy(buffer, offset - 4, size, 0, 4);
                            frameSize = hexToDec(size);
                            if (frameSize <= 0) {
                                offset++;
                            } else if (frameSize > 0xfffff) {
                                offset++;
                            } else if (offset + frameSize <= leaveSize) {
                                offset += frameSize;
                            } else {
                                break;
                            }
                        } else
                            offset++;
                    } else {
                        if (offset + 1 <= leaveSize) {
                            offset++;
                        } else {
                            break;
                        }
                    }
                }
                if (read < BUFSIZE) {
                    out.write(buffer, 0, read);

                    break;

                }
                offset -= 4;
                out.write(buffer, 0, offset);
                in.seek(offset);
                offset = 0;
                read = in.read(buffer);
                leaveSize = offset + read;

            }
            in.close();
            out.close();
        }
    }

    public static void decrypt(@NotNull String file, String securePath, String localPath, String MasterPath) throws Exception {
        String psrc = securePath + "\\" + file;
        String pdes = localPath + "\\" + file.replace(".SCS", "");

        String src = cleanString(psrc);
        String des = cleanString(pdes);

        if (src == "false" || des == "false") {
            wrongPopup("wrong file Path");
        } else {

            byte[] iv = new byte[16];
            byte[] key = new byte[32];
            int mdatOffset = 0;

            int offset = 0;
            int frameSize = 0;

            InputStream din = new FileInputStream(src);
            OutputStream out = new FileOutputStream(des);

            byte[] keyAndIv = Crypto.decrypt(din, MasterPath);
            din.close();
            System.arraycopy(keyAndIv, 0, key, 0, 32);
            System.arraycopy(keyAndIv, 32, iv, 0, 16);
            RandomAccessFile in = new RandomAccessFile(src, "r");
            in.seek(keyAndIv.length);

            byte[] buffer = new byte[BUFSIZE];

            byte[] size = new byte[4];
            int read = in.read(buffer);
            int leaveSize = read;
            //find mdat offset
            while (true) {
                mdatOffset++;
                if (buffer[mdatOffset] == 0x6d) { //m
                    if (buffer[mdatOffset + 1] == 0x64 && buffer[mdatOffset + 2] == 0x61 && buffer[mdatOffset + 3] == 0x74) {
                        System.arraycopy(buffer, mdatOffset - 4, size, 0, 4);

                        offset = mdatOffset;
                        break;
                    } else if (buffer[mdatOffset + 1] == 0x6f && buffer[mdatOffset + 2] == 0x6f && buffer[mdatOffset + 3] == 0x76) {
                        System.arraycopy(buffer, mdatOffset - 4, size, 0, 4);
                        mdatOffset += hexToDec(size);
                    }
                }
            }


            //find frame
            while (true) {
                while (true) {
                    if (offset > read - 7) {
                        break;
                    }
                    if (buffer[offset] == 0x65) {
                        if (buffer[offset + 1] + 0x100 == 0x88) {
                            byte test = (byte) (buffer[offset + 2] >> 4);
                            if (test + 16 == 0x8) {
                                System.arraycopy(buffer, offset - 4, size, 0, 4);
                                frameSize = hexToDec(size);
                                if (frameSize <= 0) {
                                    offset++;
                                } else if (frameSize > 0xffffff) {
                                    offset++;
                                } else if (offset + frameSize <= leaveSize) {

                                    byte[] target = new byte[frameSize];
                                    System.arraycopy(buffer, offset + 3, target, 0, frameSize - 3);
                                    byte[] decrypt = Crypto.decrypt(target, key, iv);
                                    System.arraycopy(decrypt, 0, buffer, offset + 3, frameSize - 3);
                                    offset += frameSize;
                                } else {
                                    break;
                                }
                            } else
                                offset++;
                        } else {
                            offset++;
                        }
                    } else if (buffer[offset] == 0x41) {
                        if (buffer[offset + 1] + 0x100 == 0x9a || buffer[offset + 1] + 0x100 == 0x9b) {
                            System.arraycopy(buffer, offset - 4, size, 0, 4);
                            frameSize = hexToDec(size);
                            if (frameSize <= 0) {
                                offset++;
                            } else if (frameSize > 0xfffff) {
                                offset++;
                            } else if (offset + frameSize <= leaveSize) {
                                byte[] target = new byte[frameSize];
                                System.arraycopy(buffer, offset + 3, target, 0, frameSize - 3);
                                byte[] decrypt = Crypto.decrypt(target, key, iv);
                                System.arraycopy(decrypt, 0, buffer, offset + 3, frameSize - 3);
                                offset += frameSize;
                            } else {
                                break;
                            }
                        } else if (buffer[offset + 1] + 0x100 == 0x9e || buffer[offset + 1] + 0x100 == 0x9f) {
                            System.arraycopy(buffer, offset - 4, size, 0, 4);
                            frameSize = hexToDec(size);
                            if (frameSize <= 0) {
                                offset++;
                            } else if (frameSize > 0xfffff) {
                                offset++;
                            } else if (offset + frameSize <= leaveSize) {
                                offset += frameSize;
                            } else {
                                break;
                            }
                        } else
                            offset++;
                    } else if (buffer[offset] == 0x01) {
                        if (buffer[offset + 1] + 0x100 == 0x9e || buffer[offset + 1] + 0x100 == 0x9f) {
                            System.arraycopy(buffer, offset - 4, size, 0, 4);
                            frameSize = hexToDec(size);
                            if (frameSize <= 0) {
                                offset++;
                            } else if (frameSize > 0xfffff) {
                                offset++;
                            } else if (offset + frameSize <= leaveSize) {
                                offset += frameSize;
                            } else {
                                break;
                            }
                        } else
                            offset++;
                    } else {
                        if (offset + 1 <= leaveSize) {
                            offset++;
                        } else {
                            break;
                        }
                    }
                }
                if (read < BUFSIZE) {
                    out.write(buffer, 0, read);

                    break;

                }
                offset -= 4;
                out.write(buffer, 0, offset);
                in.seek(offset);
                offset = 0;
                read = in.read(buffer);
                leaveSize = offset + read;

            }

            in.close();
            out.close();
        }
    }

    /**
     * @param tableLength 테이블 길이(Byte)
     * @return 테이블 길이(int)
     */
    public static int hexToDec(byte[] tableLength) {
        int length = 0;
        int mult = 1;

        for (int i = 0; i < 4; ++i) {
            if (tableLength[4 - 1 - i] < 0) {
                length += mult * (tableLength[4 - 1 - i] + 0x100);
            } else {
                length += mult * tableLength[4 - 1 - i];
            }
            mult <<= 8;
        }
        return length;
    }

}
