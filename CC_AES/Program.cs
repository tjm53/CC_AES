using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;

namespace CC_AES
{

    class Program
    {
        //test
        static void Main(string[] args)
        {

        //help messages
        string helpLANunciph = "- For LAN L7 unciphering, please enter \"-LAN -UNCIPHER L6Vers(000 or 001) L2cipheredFrame Kmac Kenc\"";

        string helpLANciphV0 = "- For LAN L2 ciphering LAN protocol version 000, please enter \"-LAN -CIPHER L6Vers(000) L7uncipheredFrame Kenc M-field A-field L6Cpt C-field KeyNumber(decimal)\"";
        string helpLANciphV1 = "- For LAN L2 ciphering LAN protocol version 001, please enter \"-LAN -CIPHER L6Vers(001) L7uncipheredFrame(MSB) Kenc(MSB) M-field(LSB) A-field(LSB) L6Cpt C-field KeyNumber(decimal) L6OprID L6App CI-field\"";

        string helpNFCunciph = "- For NFC unciphering, please enter \"-NFC -UNCIPHER NFCcipheredFrame Kmob NFCUID\"";
        string helpDebug = "- You can enter DEBUG mode by adding \"-DEBUG\" at the end of the command e.g: \"-LAN L2InputFrame Kmac Kenc -DEBUG\"";
        
        //debug mode
        bool DEBUG = false;

        if (args.Length == 0)
            System.Console.WriteLine("/!\\ No argument.  Use the command \" -HELP\" for synthax requirements" + Environment.NewLine);
        else
        {

            if (args[args.Length - 1].ToUpper() == "-DEBUG")
                DEBUG = true;

            switch (args[0].ToUpper())
            {
                case "-LAN":
                    switch (args[1].ToUpper())
                    {
                        case "-UNCIPHER":
                            if (args[2] == "000")
                            {
                                System.Console.WriteLine("LAN unciphering L6vers=000");
                                LANuncipherV0(args, DEBUG);
                                break;
                            }
                            else if (args[2] == "001")
                            {
                                System.Console.WriteLine("LAN unciphering L6vers=001");
                                LANuncipherV1(args, DEBUG);
                                break;
                            }
                            else
                            {
                                System.Console.WriteLine("The only supported LAN protocol versions are 000 and 001");
                                break;
                            }

                        case "-CIPHER":
                            if (args[2] == "000")
                            {
                                System.Console.WriteLine("LAN ciphering L6vers=000");
                                LANcipherV0(args, DEBUG);
                                break;
                            }
                            else if (args[2] == "001")
                            {
                                System.Console.WriteLine("LAN ciphering L6vers=001");
                                LANcipherV1(args, DEBUG);
                                break;
                            }
                            else
                            {
                                System.Console.WriteLine("The only supported LAN protocol versions are 000 and 001");
                                break;
                            }
                    }
                    break;
                case "-NFC":
                    switch (args[1].ToUpper())
                    {
                        case "-UNCIPHER":                                                      
                            System.Console.WriteLine("NFC Unciphering");
                            NFCuncipher(args, DEBUG);
                            break;
                        case "-CIPHER":
                            System.Console.WriteLine("NFC ciphering (not implemented yet)");
                            break;
                    }
                    break;
                case "-CIPH":
                    {
                        System.Console.WriteLine("DATA Ciphering");
                        NFCDATAcipher(args, DEBUG);
                    }
                    break;

                case "-HELP":
                    System.Console.WriteLine(helpLANunciph + Environment.NewLine + helpLANciphV0 + Environment.NewLine + helpLANciphV1 + Environment.NewLine + helpNFCunciph + Environment.NewLine + helpDebug);
                    break;
                default:
                    System.Console.WriteLine("/!\\ Wrong arguments.  Use the command \" -HELP\" for synthax requirements" + Environment.NewLine);
                    break;
            }

        }
     
            
        }

        private static void NFCDATAcipher(string[] args, bool DEBUG)
        {
            string data = args[1];
            byte[] kencbytes = Hex2Bytes(args[2].Substring(0, 32));
            string IV = (args[3].ToString().PadRight(32, '0'));
                       
            //chiffrement 
            byte[] DATAcipheredbytes = CAES128.AES_CTR(Hex2Bytes(data), kencbytes, Hex2Bytes(IV));
            string DATAciphered = Bytes2Hex(DATAcipheredbytes, DATAcipheredbytes.Length);
            //System.Console.WriteLine("LAN L7 ciphered: " + l7ciphered);

            System.Console.WriteLine("CipheredData " + DATAciphered);
        }

        private static void LANuncipherV0(string[] args, bool DEBUG)
        {
            //conversion des arguments
            string input_frame = args[3];
            byte[] kmacbytes = Hex2Bytes(args[4].Substring(0, 32));
            byte[] kencbytes = Hex2Bytes(args[5].Substring(0, 32));

            //décodage l6
            string l6 = input_frame.Substring(22, input_frame.Length - 26);

            string l6ctrl = Convert.ToString(byte.Parse(l6.Substring(0, 2), System.Globalization.NumberStyles.HexNumber), 2).PadLeft(8, '0');
            string lblL6Vers = l6ctrl.Substring(0, 3);
            string lblL6Wts = l6ctrl.Substring(3, 1);
            //string lblL6KeySel = l6ctrl.Substring(4, 4);
            //system.Console.WriteLine("Clé n° : " + Convert.ToInt32(lblL6KeySel.ToString(), 2).ToString());

               //Décodage trame
                string lblMField = input_frame.Substring(4, 4);
                string lblAField = input_frame.Substring(8, 12);
                string lblClField = input_frame.Substring(20, 2);
                int cfield = Int32.Parse(input_frame.Substring(2, 2), System.Globalization.NumberStyles.HexNumber);
                string lblCField = cfield.ToString("X2");

                string lblL6Cpt = l6.Substring(2, 4);
                string lblL6HashKmac = l6.Substring(l6.Length - 4, 4);

                if (CRC_OK(input_frame, DEBUG) && hashKmac_OK(input_frame, kmacbytes, lblL6Vers, DEBUG) && hashKenc_OK(input_frame, kencbytes, lblL6Vers, DEBUG))
                {

                    string l7 = (lblL6Wts.ToString() == "1") ? l6.Substring(6, l6.Length - 22) : l6.Substring(6, l6.Length - 18);

                    string txtIV = (lblMField.ToString() + lblAField.ToString() + lblL6Cpt.ToString() + lblCField.ToString()).PadRight(32, '0');

                    byte[] l7decipheredbytes = CAES128.AES_CTR(Hex2Bytes(l7), kencbytes, Hex2Bytes(txtIV));
                    string l7deciphered = Bytes2Hex(l7decipheredbytes, l7decipheredbytes.Length);

                    if (DEBUG) { System.Console.WriteLine("IV: " + txtIV + Environment.NewLine + Environment.NewLine + "L7 ciphered: " + l7); }

                    System.Console.WriteLine("L7 unciphered: " + l7deciphered);
                }
   
        }
        private static void LANuncipherV1(string[] args, bool DEBUG)
        {
            //conversion des arguments
            string input_frame = args[3];
            byte[] kmacbytes = Hex2Bytes(args[4].Substring(0, 32));
            byte[] kencbytes = Hex2Bytes(args[5].Substring(0, 32));

            //décodage l6
            string l6 = input_frame.Substring(22, input_frame.Length - 26);

            string l6ctrl = Convert.ToString(byte.Parse(l6.Substring(0, 2), System.Globalization.NumberStyles.HexNumber), 2).PadLeft(8, '0');
            string lblL6Vers = l6ctrl.Substring(0, 3);
            string lblL6Wts = l6ctrl.Substring(3, 1);
            string lblL6KeySel = l6ctrl.Substring(4, 4);
            //system.Console.WriteLine("Clé n° : " + Convert.ToInt32(lblL6KeySel.ToString(), 2).ToString());
              
                //Décodage trame
                int cfield = Int32.Parse(input_frame.Substring(2, 2), System.Globalization.NumberStyles.HexNumber);
                string lblCField = cfield.ToString("X2");
                string lblMField = input_frame.Substring(4, 4);
                string lblAField = input_frame.Substring(8, 12);
                string lblClField = input_frame.Substring(20, 2);

                string lblL6OprID = l6.Substring(2, 2);
                string lblL6Cpt = l6.Substring(4, 4);
                string lblL6App = l6.Substring(8, 2);
                string lblL6HashKmac = l6.Substring(l6.Length - 4, 4);

                if (CRC_OK(input_frame, DEBUG) && hashKmac_OK(input_frame, kmacbytes, lblL6Vers, DEBUG) && hashKenc_OK(input_frame, kencbytes, lblL6Vers, DEBUG))
                {

                    string l7 = l6.Substring(10, l6.Length - 26);

                    string txtIV = (lblMField.ToString() + lblAField.ToString() + lblL6Cpt.ToString() + lblCField.ToString()).PadRight(32, '0');

                    byte[] l7decipheredbytes = CAES128.AES_CTR(Hex2Bytes(l7), kencbytes, Hex2Bytes(txtIV));
                    string l7deciphered = Bytes2Hex(l7decipheredbytes, l7decipheredbytes.Length);

                    if (DEBUG) { System.Console.WriteLine("IV: " + txtIV + Environment.NewLine + Environment.NewLine + "L7 ciphered: " + l7); }

                    System.Console.WriteLine("L7 unciphered: " + l7deciphered);
                }
            
            else
            {
                System.Console.WriteLine("Frame unciphering error");
            }
        }

        private static void LANcipherV0(string[] args, bool DEBUG)
        {
            string lblL6Vers = args[2];            
            string l7 = args[3];
            byte[] kencbytes = Hex2Bytes(args[4].Substring(0, 32));
            string lblMField = args[5];
            string lblAField = args[6];
            string lblL6Cpt = args[7];
            string lblCField = args[8];

            string lblL6Wts = "1";
            string lblL6KeySel = Convert.ToString(Convert.ToInt32(args[9], 10), 2).PadLeft(4, '0');
            string lblL6Ctrl = Convert.ToInt32(lblL6Vers + lblL6Wts + lblL6KeySel, 2).ToString("X2");

            //System.Console.WriteLine("lblL6Ctrl  : " + lblL6Ctrl);
            //System.Console.WriteLine("l7: " + l7 + Environment.NewLine + "lblMField: " + lblMField + Environment.NewLine + "lblAField: " + lblAField + Environment.NewLine + "lblL6Cpt: " + lblL6Cpt + Environment.NewLine + "lblCField: " + lblCField + Environment.NewLine + "l7: " + l7 + Environment.NewLine);

            //IV
            string txtIV = (lblMField.ToString() + lblAField.ToString() + lblL6Cpt.ToString() + lblCField.ToString()).PadRight(32, '0');
            //System.Console.WriteLine("computed IV: " + txtIV);
            //chiffrement L7
            byte[] l7cipheredbytes = CAES128.AES_CTR(Hex2Bytes(l7), kencbytes, Hex2Bytes(txtIV));
            string l7ciphered = Bytes2Hex(l7cipheredbytes, l7cipheredbytes.Length);
            //System.Console.WriteLine("LAN L7 ciphered: " + l7ciphered);


            string lblCIField = "B4"; // imposée par la LAN

            string lblL6HashKenc = "00000000"; //recalcule après
            string lblL6Tstamp = "0000"; //recalculé par le K
            string lblL6HashKmac = "0000"; //recalculé par le K
            string CRC = "0000"; //recalculé par le K
            //L-field
            Int32 lfield_calc = 1 + 2 + 6 + 1 + 1 + 2 + l7.Length / 2 + 4 + lblL6Tstamp.Length / 2 + 2 + 2; // longeur de la trame du C-field au CRC inclu
            string lblLField = lfield_calc.ToString("X2");

            lblL6HashKenc = Bytes2Hex(CAES128.AES_CMAC(Hex2Bytes(lblLField + lblCField + lblMField + lblAField + lblCIField + lblL6Ctrl + lblL6Cpt + l7ciphered), kencbytes), 4);
            //System.Console.WriteLine("lblL6HashKenc " + lblL6HashKenc);

            string L2 = lblLField + lblCField + lblMField + lblAField + lblCIField + lblL6Ctrl + lblL6Cpt + l7ciphered + lblL6HashKenc + lblL6Tstamp + lblL6HashKmac + CRC;
            System.Console.WriteLine("L2 " + L2);
        }
        private static void LANcipherV1(string[] args, bool DEBUG)
        {
            string lblCField = args[8];
            string lblMField = args[5];
            string lblAField = args[6];
            string lblCIField = args[12]; //"B4";  imposée par la LAN

            string lblL6Vers = args[2];
            string lblL6Wts = "0"; //champs reserved du L6Ctrl fixé à 0
            string lblL6KeySel = Convert.ToString(Convert.ToInt32(args[9], 10), 2).PadLeft(4, '0');
            string lblL6Ctrl = Convert.ToInt32(lblL6Vers + lblL6Wts + lblL6KeySel, 2).ToString("X2");

            string lblL6OprID = args[10];
            string lblL6Cpt = args[7];
            string lblL6App = args[11];

            string l7 = args[3];

            string lblL6HashKenc = "00000000"; //recalcule après
            string lblL6Tstamp = "0000"; //recalculé par le K
            string lblL6HashKmac = "0000"; //recalculé par le K
            string CRC = "0000"; //recalculé par le K

            byte[] kencbytes = Hex2Bytes(args[4].Substring(0, 32));
 
            
            //System.Console.WriteLine("l7: " + l7 + Environment.NewLine + "lblMField: " + lblMField + Environment.NewLine + "lblAField: " + lblAField + Environment.NewLine + "lblL6Cpt: " + lblL6Cpt + Environment.NewLine + "lblCField: " + lblCField + Environment.NewLine + "l7: " + l7 + Environment.NewLine);

            //IV
            string txtIV = (lblMField.ToString() + lblAField.ToString() + lblL6Cpt.ToString() + lblCField.ToString()).PadRight(32, '0');
            if (DEBUG) { System.Console.WriteLine("computed IV: " + txtIV); }

            //chiffrement L7
            byte[] l7cipheredbytes = CAES128.AES_CTR(Hex2Bytes(l7), kencbytes, Hex2Bytes(txtIV));
            string l7ciphered = Bytes2Hex(l7cipheredbytes, l7cipheredbytes.Length);

            if (DEBUG) { System.Console.WriteLine("LAN L7 ciphered: " + l7ciphered); }
            


            //L-field
            Int32 lfield_calc = 1 + 2 + 6 + 1 + 1 + 1 + 2 + 1 + l7.Length / 2 + 4 + lblL6Tstamp.Length / 2 + 2 + 2; // longeur de la trame du C-field au CRC inclu
            string lblLField = lfield_calc.ToString("X2");

            //L6HashKenc
            string block0 = lblMField + lblAField + lblL6Cpt + "000000000000";
            lblL6HashKenc = Bytes2Hex(CAES128.AES_CMAC(Hex2Bytes(block0 + l7ciphered), kencbytes), 4);
            if (DEBUG) { System.Console.WriteLine("lblL6HashKenc " + lblL6HashKenc); } 

            string L2 = lblLField + lblCField + lblMField + lblAField + lblCIField + lblL6Ctrl + lblL6OprID + lblL6Cpt + lblL6App + l7ciphered + lblL6HashKenc + lblL6Tstamp + lblL6HashKmac + CRC;
            System.Console.WriteLine("L2 " + L2);
        }

        private static void NFCuncipher(string[] args, bool DEBUG)
        {
            //input_NFCframe kmob NFCUid (8o)
            string input_NFCframe = args[2];
            byte[] kmobbytes = Hex2Bytes(args[3].Substring(0, 32));
            string NFCuid = args[4];

            string NFCLfield = input_NFCframe.Substring(0, 2);
            string NFCcpt = input_NFCframe.Substring(2, 4);
            string NFCCfield = input_NFCframe.Substring(6, 2);
            string NFCNFCver = input_NFCframe.Substring(8, 2);
            string NFCdata = input_NFCframe.Substring(10, input_NFCframe.Length - 22);
            string NFChashkmob = input_NFCframe.Substring(input_NFCframe.Length - 12, 8);
            string NFCCRC = input_NFCframe.Substring(input_NFCframe.Length - 4, 4);
            /*
            System.Console.WriteLine("NFCLfield " + NFCLfield);
            System.Console.WriteLine("NFCcpt " + NFCcpt);
            System.Console.WriteLine("NFCCfield " + NFCCfield);
            System.Console.WriteLine("NFCNFCver " + NFCNFCver);
            System.Console.WriteLine("NFCdata " + NFCdata);
            System.Console.WriteLine("NFChashkmob " + NFChashkmob);
            System.Console.WriteLine("NFCCRC " + NFCCRC);
             */

            //CRC vérification
            if (CRC_OK(input_NFCframe, DEBUG))
            {

                //hashKmob vérification
                string NFCinputhashkmob = (NFCuid.ToString() + NFCLfield.ToString() + NFCcpt.ToString() + NFCCfield.ToString() + NFCNFCver.ToString() + NFCdata.ToString());

                string NFChashkmobcomputed = Bytes2Hex(CAES128.AES_CMAC(Hex2Bytes(NFCinputhashkmob), kmobbytes), 4);
                if (DEBUG) { System.Console.WriteLine("NFChashkmobcomputed " + NFChashkmobcomputed.ToString().ToUpper() + " NFChashkmob_inframe " + NFChashkmob); }
                

                if (NFChashkmobcomputed.ToString().ToUpper() == NFChashkmob)
                {
                    //déchiffrement
                    //calcul IV


                    string NFCIV = (NFCuid.ToString() + NFCcpt.ToString()).PadRight(32, '0');
                    if (DEBUG) { System.Console.WriteLine("NFCIV: " + NFCIV); }


                    byte[] NFCdecipheredbytes = CAES128.AES_CTR(Hex2Bytes(NFCdata), kmobbytes, Hex2Bytes(NFCIV));
                    string NFCl7deciphered = Bytes2Hex(NFCdecipheredbytes, NFCdecipheredbytes.Length);
                    System.Console.WriteLine("NFC L7: " + NFCl7deciphered);


                }
                else
                {
                    System.Console.WriteLine("Error HashKmob: HashKmob computed = " + NFChashkmobcomputed.ToString().ToUpper() + " HashKmob in frame = " + NFCinputhashkmob);
                }

            }
        }

        private static byte[] Hex2Bytes(string hex)
        {
            // On vérifie que la chaine a bien une longueur paire
            if (hex.Length % 2 != 0)
            {
                throw new ArgumentException("hex", "hex doit être de longueur paire");
            }

            // On traite les caractères 2 par 2 pour les transformer
            byte[] hexAsBytes = new byte[hex.Length / 2];
            for (int index = 0; index < hexAsBytes.Length; index++)
            {
                string byteValue = hex.Substring(index * 2, 2);
                hexAsBytes[index] = byte.Parse(byteValue, System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture);
            }

            return hexAsBytes;
        }

        private static string Bytes2Hex(byte[] data, int length)
        {
            string answer = "";
            int i = 0;
            while (i < length)
            {
                answer += data[i].ToString("X2");
                i++;
            }
            return answer;
        }

        private static bool CRC_OK(string input_frame, bool DEBUG)
        {
  
            string lblCRC = input_frame.Substring(input_frame.Length - 4, 4);

            //Si le CRC a été forcé à 0 (trame issu de flux WAN)
            if (lblCRC == "0000")
            {
                if (DEBUG) { System.Console.WriteLine(Environment.NewLine + "CRC = 0000 -> Continue (the frame presumably comes from a WAN message with a CRC forced to 0000"); }
                return true;

            }
                //sinon on calcule le CRC et vérifie qu'il est OK avec celui de la trame
                else
                {                               
                    //calcul du CRC
                    string CRCinput = input_frame.Substring(0, input_frame.Length - 4);
                    byte[] CRCinputbytes = Hex2Bytes(CRCinput);
                    short CRCcomputed = CLibCRC.CalculateCRC16EN13757(CRCinputbytes);
                    string lblCRCcomputed = CRCcomputed.ToString("X2");
                                    
                    //vérification du CRC calculé et du CRC de la trame
                    if (lblCRCcomputed.ToString().ToUpper().PadLeft(4, '0') == lblCRC.ToString().ToUpper())
                    {
                        if (DEBUG) { System.Console.WriteLine(Environment.NewLine + "CRC OK" + " CRC computed = " + lblCRCcomputed + " CRC in frame = " + lblCRC);



                        
                        }
                        return true;
                    }
                    else
                    {
                        System.Console.WriteLine("Error CRC: CRC computed = " + lblCRCcomputed + " CRC in frame = " + lblCRC);
                        return false;

                    }
                }
            }

        private static bool hashKmac_OK(string input_frame, byte[] kmacbytes, string lblL6Vers, bool DEBUG)
        {

            //hashKmac de la trame
            string l6 = input_frame.Substring(22, input_frame.Length - 26);
            string lblL6HashKmac = l6.Substring(l6.Length - 4, 4);

            if (lblL6Vers == "000")
            {
                //calcul du hashKmac à partir de la trame
                string Cmacinput = input_frame.Substring(0, input_frame.Length - 8);
                byte[] Cmacinputbytes = Hex2Bytes(Cmacinput);
                string lblL6HashKmaccomputed = Bytes2Hex(CAES128.AES_CMAC(Cmacinputbytes, kmacbytes), 2);

                if (DEBUG) System.Console.WriteLine(Environment.NewLine + "full hashKmac computed = " + Bytes2Hex(CAES128.AES_CMAC(Cmacinputbytes, kmacbytes), 16));

                if (lblL6HashKmaccomputed.ToString().ToUpper() == lblL6HashKmac.ToString().ToUpper())
                {
                    if (DEBUG) { System.Console.WriteLine("hashKmac computed = " + lblL6HashKmaccomputed + " hashKmac in frame = " + lblL6HashKmac + Environment.NewLine + "hashKmac OK"); }
                    return true;
                }
                else
                {
                    System.Console.WriteLine("Error hashKmac: hashKmac computed = " + lblL6HashKmaccomputed + " hashKmac in frame = " + lblL6HashKmac);
                    if (DEBUG) { return true; } else { return false; }

                }
            }

            else if (lblL6Vers == "001")
            {
                //calcul du hashKmac à partir de la trame
                string lblMField = input_frame.Substring(4, 4);
                string lblAField = input_frame.Substring(8, 12);
                string block0 = lblMField + lblAField + "0000000000000000";

                string Cmacinput = block0 + l6.Substring(0, l6.Length - 4);
                byte[] Cmacinputbytes = Hex2Bytes(Cmacinput);
                string lblL6HashKmaccomputed = Bytes2Hex(CAES128.AES_CMAC(Cmacinputbytes, kmacbytes), 2);

                if (DEBUG) System.Console.WriteLine(Environment.NewLine + "full hashKmac computed = " + Bytes2Hex(CAES128.AES_CMAC(Cmacinputbytes, kmacbytes), 16));

                if (lblL6HashKmaccomputed.ToString().ToUpper() == lblL6HashKmac.ToString().ToUpper())
                {
                    if (DEBUG) { System.Console.WriteLine("hashKmac computed = " + lblL6HashKmaccomputed + " hashKmac in frame = " + lblL6HashKmac + Environment.NewLine + "hashKmac OK"); }
                    return true;
                }
                else
                {
                    System.Console.WriteLine("Error hashKmac: hashKmac computed = " + lblL6HashKmaccomputed + " hashKmac in frame = " + lblL6HashKmac);
                    if (DEBUG) { return true; } else { return false; }

                }
            }
            else
            {
                return false;
            }
                                              
        }

        private static bool hashKenc_OK(string input_frame, byte[] kencbytes, string lblL6Vers, bool DEBUG)
        {
            //hashKenc de la trame
            string lblL6HashKenc;
            string Cencinput = "";

           
            if (lblL6Vers == "000")
            {
                string l6 = input_frame.Substring(22, input_frame.Length - 26);
                string l6ctrl = Convert.ToString(byte.Parse(l6.Substring(0, 2), System.Globalization.NumberStyles.HexNumber), 2).PadLeft(8, '0');
                string lblL6Wts = l6ctrl.Substring(3, 1);

                if (DEBUG) { System.Console.WriteLine(" l6 = " + l6 + " l6ctrl = " + l6ctrl + " lblL6Wts = " + lblL6Wts); }

                //si L6TStamp présent
                if (lblL6Wts.ToString() == "1")
                {
                    //lblL6TStamp = l6.Substring(l6.Length - 8, 4);
                    lblL6HashKenc = l6.Substring(l6.Length - 16, 8);
                    Cencinput = input_frame.Substring(0, input_frame.Length - 20);
                }
                //si L6Tstamp absent
                else
                {
                    //lblL6TStamp = "";
                    lblL6HashKenc = l6.Substring(l6.Length - 12, 8);
                    Cencinput = input_frame.Substring(0, input_frame.Length - 16);
                }

                // System.Console.WriteLine("Cencinput = " + Cencinput + " lblL6HashKenc = " + lblL6HashKenc);


                //calcul du hashKenc à partir de la trame
                byte[] Cencinputbytes = Hex2Bytes(Cencinput);
                string lblL6HashKenccomputed = Bytes2Hex(CAES128.AES_CMAC(Cencinputbytes, kencbytes), 4);

                if (DEBUG) System.Console.WriteLine(Environment.NewLine + "full hashKenc computed = " + Bytes2Hex(CAES128.AES_CMAC(Cencinputbytes, kencbytes), 16));

                if (lblL6HashKenccomputed.ToString().ToUpper() == lblL6HashKenc.ToString().ToUpper())
                {
                    if (DEBUG) { System.Console.WriteLine("hashKenc computed = " + lblL6HashKenccomputed + " hashKenc in frame = " + lblL6HashKenc + Environment.NewLine + "hashKenc OK" + Environment.NewLine); }

                    return true;
                }
                else
                {
                    System.Console.WriteLine("Error hashKenc: hashKenc computed = " + lblL6HashKenccomputed + " hashKenc in frame = " + lblL6HashKenc);
                    if (DEBUG) { return true; } else { return false; }
                }

            }  
            else if (lblL6Vers == "001")
            {
                //calcul du hashKenc à partir de la trame
                lblL6HashKenc = input_frame.Substring(input_frame.Length - 20, 8);

                if (DEBUG) { System.Console.WriteLine(" lblL6HashKenc " + lblL6HashKenc); }

                string L7 = input_frame.Substring(32, input_frame.Length - 52); //L7

                if (DEBUG) { System.Console.WriteLine(" L7 " + L7); }

                string lblMField = input_frame.Substring(4, 4);
                string lblAField = input_frame.Substring(8, 12);
                string lblL6Cpt = input_frame.Substring(26, 4);

                string block0 = lblMField + lblAField + lblL6Cpt + "000000000000";

                Cencinput = block0 + L7;
                
                byte[] Cencinputbytes = Hex2Bytes(Cencinput);
                string lblL6HashKenccomputed = Bytes2Hex(CAES128.AES_CMAC(Cencinputbytes, kencbytes), 4);

                if (DEBUG) System.Console.WriteLine(Environment.NewLine + "full hashKenc computed = " + Bytes2Hex(CAES128.AES_CMAC(Cencinputbytes, kencbytes), 16));

                if (lblL6HashKenccomputed.ToString().ToUpper() == lblL6HashKenc.ToString().ToUpper())
                {
                    if (DEBUG) { System.Console.WriteLine("hashKenc computed = " + lblL6HashKenccomputed + " hashKenc in frame = " + lblL6HashKenc + Environment.NewLine + "hashKenc OK" + Environment.NewLine); }

                    return true;
                }
                else
                {
                    System.Console.WriteLine("Error hashKenc: hashKenc computed = " + lblL6HashKenccomputed + " hashKenc in frame = " + lblL6HashKenc);
                    if (DEBUG) { return true; } else { return false; }
                }


            }
            else
            { 
                return false;
            }
        }

        }

}