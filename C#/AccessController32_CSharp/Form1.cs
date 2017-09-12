/**
* AccessController32 2015-04-30 17:40:43 karl  $
*
* AccessController Short Packet Protocal  Test Demo Project
* V2.5 Version  2015-04-29 20:41:30 Using V6.56 driver version Model changed from 0x19 to 0x17
*      Basic Function:  Query Controller Status
*                       Get Controller Date and Time
*                       Set Controller Date and Time
*                       Get the records for the specified index number
*                       Set the read index number to be read
*                       Get the read index number that has been read
*                       Remote Open Door
*                       Permission to add or modify
*                       Permission Delete (Single Delete)
*                       Clear the permissions (all cleared)
*                       Get Permission Total Number
*                       Query Permission
*                       Set Door control parameters (online / delay)
*                       Get Door control parameters (online / delay)

*                       Set the IP and port of the receiving server
*                       Get the IP and port of the receiving server
*
*
*                       Receiving server implementation (receiving data at port 61005) - This feature must be aware that the firewall settings must be allowed to receive data.
*/

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.Windows.Forms;
using System.Diagnostics;

namespace AccessController32_CSharp
{
    public partial class Form1 : Form
    {
        /// <summary>
        /// 
        /// </summary>
        public Form1()
        {
            InitializeComponent();
        }

        Boolean bStopWatchServer = false; //2015-05-05 17:35:07 Stop the receiving server Flag
        Boolean bStopBasicFunction = false;  //2015-06-10 09:04:52 Basic Test
        private void Form1_FormClosing(object sender, FormClosingEventArgs e)
        {
            bStopWatchServer = true;
            bStopBasicFunction = true;  //2015-06-10 09:04:52 Basic Test
        }


        private void button1_Click(object sender, EventArgs e)
        {
            this.txtInfo.Text = "";

            //Stop receiving the server ID 
            bStopWatchServer = true;
            bStopBasicFunction = false;  //2015-06-10 09:04:52 Basic Test

            //'    'This case did not work as a search controller and set up IP (done directly by the IP setup tool)
            //'    'The test description in this case
            //'    'Controller SN  = 229999901
            //'    'Controller IP  = 192.168.168.123
            //'    'Computer  IP  = 192.168.168.101
            //'    'Used as the receiving server IP (the computer IP 192.168.168.101), the receiving server port (61005)

            //Basic Function Test
            //txtSN.Text Controller 9-digit SN
            //txtIP.Text Controller IP address, the default using 192.168.168.123 [can use the Search Controller to modify the controller IP]
            testBasicFunction(txtIP.Text, long.Parse(txtSN.Text));


            //txtWatchServerIP.Text  Receive the server IP, the default use of computer IP 192.168.168.101 [can also use Search Controller modify settings]
            //txtWatchServerPort.Text  Receive the server's PORT, Default 61005
            testWatchingServer(txtIP.Text, long.Parse(txtSN.Text), txtWatchServerIP.Text, int.Parse(this.txtWatchServerPort.Text)); //Receive server settings

            bStopWatchServer = false;
            WatchingServerRuning(txtWatchServerIP.Text, int.Parse(this.txtWatchServerPort.Text)); //Server Running....
            bStopWatchServer = true;
        }


        private void button2_Click(object sender, EventArgs e)
        {
            bStopWatchServer = true;
            bStopBasicFunction = true;  //2015-06-10 09:04:52 Basic Test
        }

        private void button3_Click(object sender, EventArgs e) //2015-05-05 17:35:35 Search Access Controller
        {
            try
            {
                ProcessStartInfo pInfo = new ProcessStartInfo();
                pInfo.FileName = Environment.CurrentDirectory + "\\WEBConfigV2.7_EN.exe";
                pInfo.UseShellExecute = true;
                Process p = Process.Start(pInfo);
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex.ToString());
                MessageBox.Show(ex.ToString());

            }
        }
        private void button4_Click(object sender, EventArgs e)
        {
            bStopWatchServer = false;
            WatchingServerRuning(txtWatchServerIP.Text, int.Parse(this.txtWatchServerPort.Text)); //Server Running....
            bStopWatchServer = true;
        }

        /// <summary>
        /// Short Packet
        /// </summary>
        class AccessPacketShort
        {
            public static int WGPacketSize = 64;			    //Short Packet Length
            //2015-04-29 22:22:41 const static unsigned char	 Type = 0x19;					//Type
            public static int Type = 0x17;		//2015-04-29 22:22:50			//Type
            public static int ControllerPort = 60000;        //Access Controller' Port
            public static long SpecialFlag = 0x55AAAA55;     //Special logo to prevent misuse

            public int functionID;		                     //Function ID
            public long iDevSn;                              //Deceive Serial Number(Controller) four bytes, nine dec number
            public string IP;                                //Access Controller' IP Address

            public byte[] data = new byte[56];               //56 bytes of data [including sequenceId]
            public byte[] recv = new byte[WGPacketSize];     //Receive Data buffer

            public AccessPacketShort()
            {
                Reset();
            }
            public void Reset()  //Data reset
            {
                for (int i = 0; i < 56; i++)
                {
                    data[i] = 0;
                }
            }
            static long sequenceId;     //
            public byte[] toByte() //Generates a 64-byte short package
            {
                byte[] buff = new byte[WGPacketSize];
                sequenceId++;

                buff[0] = (byte)Type;
                buff[1] = (byte)functionID;
                Array.Copy(System.BitConverter.GetBytes(iDevSn), 0, buff, 4, 4);
                Array.Copy(data, 0, buff, 8, data.Length);
                Array.Copy(System.BitConverter.GetBytes(sequenceId), 0, buff, 40, 4);
                return buff;
            }

            WG3000_COMM.Core.wgMjController controller = new WG3000_COMM.Core.wgMjController();
            public int run()  //send command ,receive return command
            {
                byte[] buff = toByte();

                int tries = 3;
                int errcnt = 0;
                controller.IP = IP;
                controller.PORT = ControllerPort;
                do
                {
                    if (controller.ShortPacketSend(buff, ref recv) < 0)
                    {
                        return -1;
                    }
                    else
                    {
                        //sequenceId
                        long sequenceIdReceived = 0;
                        for (int i = 0; i < 4; i++)
                        {
                            long lng = recv[40 + i];
                            sequenceIdReceived += (lng << (8 * i));
                        }

                        if ((recv[0] == Type)                       //Type consistent
                            && (recv[1] == functionID)              //Function ID is consistent
                            && (sequenceIdReceived == sequenceId))  //Controller'Serial number  correspondence
                        {
                            return 1;
                        }
                        else
                        {
                            errcnt++;
                        }
                    }
                } while (tries-- > 0); //Retry three times

                return -1;
            }
            /// <summary>
            /// The last issue of the serial number(xid)
            /// </summary>
            /// <returns></returns>
            public static long sequenceIdSent()// 
            {
                return sequenceId; // The last issue of the serial number(xid)
            }
            /// <summary>
            /// close 
            /// </summary>
            public void close()
            {
                controller.Dispose();
            }
        }

        void log(string info)  //log infomation
        {
            //txtInfo.Text += string.Format("{0}\r\n", info);
            txtInfo.AppendText(string.Format("{0}\r\n", info));
            txtInfo.ScrollToCaret();//Scroll to the cursor
            Application.DoEvents();
        }

        /// <summary>
        /// 4 bytes into the integer number (low before the high)
        /// </summary>
        /// <param name="buff">bytearray</param>
        /// <param name="start">Start index bit (starting from 0)</param>
        /// <param name="len">length</param>
        /// <returns>Integer number</returns>
        long byteToLong(byte[] buff, int start, int len)
        {
            long val = 0;
            for (int i = 0; i < len && i < 4; i++)
            {
                long lng = buff[i + start];
                val += (lng << (8 * i));  
            }
            return val;
        }

        /// <summary>
        /// Integer is converted to a 4-byte array
        /// </summary>
        /// <param name="outBytes">array</param>
        /// <param name="startIndex">Start index bit (starting from 0)</param>
        /// <param name="val">value</param>
        void LongToBytes(ref byte[] outBytes, int startIndex, long val)
        {
            Array.Copy(System.BitConverter.GetBytes(val), 0, outBytes, startIndex, 4);
        }
        /// <summary>
        /// Get Hex values, mainly used for date and time format
        /// </summary>
        /// <param name="val">Value</param>
        /// <returns>Hex Value</returns>
        int GetHex(int val)
        {
            return ((val % 10) + (((val - (val % 10)) / 10) % 10) * 16);
        }

        /// <summary>
        /// Display Record Infomation
        /// </summary>
        /// <param name="recv"></param>
        void displayRecordInformation(byte[] recv)
        {
            //8-11	Record the index number
            //(=0 no record)	4	0x00000000
            int recordIndex = 0;
            recordIndex = (int)byteToLong(recv, 8, 4);

            //12	Record Type**********************************************
            //0=no record
            //1=swipe card record
            //2=Door, button, device start, remote door open record
            //3=alarm record	1	
            //0xFF=Indicates that the record of the specified index bit has been overwritten. Please use index 0 to retrieve the index value of the earliest record
            int recordType = recv[12];

            //13	Vality(0 Not allowed to pass, 1 Allowed to pass)	1	
            int recordValid = recv[13];

            //14	Door Number(1,2,3,4)	1	
            int recordDoorNO = recv[14];

            //15	Door In/Door Out(1 In Door, 2 Out Door)	1	0x01
            int recordInOrOut = recv[15];

            //16-19	Card Number(Type is when the swipe card is recorded)
            //Or number (other types of records)	4	
            long recordCardNO = 0;
            recordCardNO = byteToLong(recv, 16, 4);

            //20-26	Swipe card time:
            //The date and time seconds (using the BCD code) See the description of the setup time section
            string recordTime = "2000-01-01 00:00:00";
            recordTime = string.Format("{0:X2}{1:X2}-{2:X2}-{3:X2} {4:X2}:{5:X2}:{6:X2}",
                recv[20], recv[21], recv[22], recv[23], recv[24], recv[25], recv[26]);
            //2012.12.11 10:49:59	7	
            //27	Record the ResonNO(You can check the "swipe card record description. Xls" file ReasonNO)
            //Dealing with complex information	1	
            int reason = recv[27];


            //0=no record
            //1=swipe card record
            //2=Door, button, device start, remote door open record
            //3=alarm record	1	
            //0xFF=Indicates that the record of the specified index bit has been overwritten. Please use index 0 to retrieve the index value of the earliest record
            if (recordType == 0)
            {
                log(string.Format("Index Bit={0}  no record", recordIndex));
            }
            else if (recordType == 0xff)
            {
                log(" The record of the specified index bit has been overwritten. Please use index 0 to retrieve the index value of the earliest record");
            }
            else if (recordType == 1) //2015-06-10 08:49:31 Displays data whose record type is card number
            {
                //Card Number
                log(string.Format("Index Bit={0}  ", recordIndex));
                log(string.Format("  Card Number = {0}", recordCardNO));
                log(string.Format("  Door Number = {0}", recordDoorNO));
                log(string.Format("  IN/OUT = {0}", recordInOrOut == 1 ? "Door In" : "Door Out"));
                log(string.Format("  Valid = {0}", recordValid == 1 ? "Pass" : "No Pass"));
                log(string.Format("  Time = {0}", recordTime));
                log(string.Format("  Description = {0}", getReasonDetailEnglish(reason)));
            }
            else if (recordType == 2)
            {
                //Other processing
                //Door, button, device start, remote door open record
                log(string.Format("Index Bit={0}  No swipe card record", recordIndex));
                log(string.Format("  Serial number = {0}", recordCardNO));
                log(string.Format("  Door Number = {0}", recordDoorNO));
                log(string.Format("  Time = {0}", recordTime));
                log(string.Format("  Description = {0}", getReasonDetailEnglish(reason)));
            }
            else if (recordType == 3)
            {
                //Other processing
                //alarm record
                log(string.Format("Index Bit={0}  alarm record", recordIndex));
                log(string.Format("  Serial number = {0}", recordCardNO));
                log(string.Format("  Door Number = {0}", recordDoorNO));
                log(string.Format("  Time = {0}", recordTime));
                log(string.Format("  Description = {0}", getReasonDetailEnglish(reason)));
            }
        }

        string[] RecordDetails =
        {
//记录原因 (类型中 SwipePass 表示通过; SwipeNOPass表示禁止通过; ValidEvent 有效事件(如按钮 门磁 超级密码开门); Warn 报警事件)
//代码  类型   英文描述  中文描述
"1","SwipePass","Swipe","刷卡开门",
"2","SwipePass","Swipe Close","刷卡关",
"3","SwipePass","Swipe Open","刷卡开",
"4","SwipePass","Swipe Limited Times","刷卡开门(带限次)",
"5","SwipeNOPass","Denied Access: PC Control","刷卡禁止通过: 电脑控制",
"6","SwipeNOPass","Denied Access: No PRIVILEGE","刷卡禁止通过: 没有权限",
"7","SwipeNOPass","Denied Access: Wrong PASSWORD","刷卡禁止通过: 密码不对",
"8","SwipeNOPass","Denied Access: AntiBack","刷卡禁止通过: 反潜回",
"9","SwipeNOPass","Denied Access: More Cards","刷卡禁止通过: 多卡",
"10","SwipeNOPass","Denied Access: First Card Open","刷卡禁止通过: 首卡",
"11","SwipeNOPass","Denied Access: Door Set NC","刷卡禁止通过: 门为常闭",
"12","SwipeNOPass","Denied Access: InterLock","刷卡禁止通过: 互锁",
"13","SwipeNOPass","Denied Access: Limited Times","刷卡禁止通过: 受刷卡次数限制",
"14","SwipeNOPass","Denied Access: Limited Person Indoor","刷卡禁止通过: 门内人数限制",
"15","SwipeNOPass","Denied Access: Invalid Timezone","刷卡禁止通过: 卡过期或不在有效时段",
"16","SwipeNOPass","Denied Access: In Order","刷卡禁止通过: 按顺序进出限制",
"17","SwipeNOPass","Denied Access: SWIPE GAP LIMIT","刷卡禁止通过: 刷卡间隔约束",
"18","SwipeNOPass","Denied Access","刷卡禁止通过: 原因不明",
"19","SwipeNOPass","Denied Access: Limited Times","刷卡禁止通过: 刷卡次数限制",
"20","ValidEvent","Push Button","按钮开门",
"21","ValidEvent","Push Button Open","按钮开",
"22","ValidEvent","Push Button Close","按钮关",
"23","ValidEvent","Door Open","门打开[门磁信号]",
"24","ValidEvent","Door Closed","门关闭[门磁信号]",
"25","ValidEvent","Super Password Open Door","超级密码开门",
"26","ValidEvent","Super Password Open","超级密码开",
"27","ValidEvent","Super Password Close","超级密码关",
"28","Warn","Controller Power On","控制器上电",
"29","Warn","Controller Reset","控制器复位",
"30","Warn","Push Button Invalid: Disable","按钮不开门: 按钮禁用",
"31","Warn","Push Button Invalid: Forced Lock","按钮不开门: 强制关门",
"32","Warn","Push Button Invalid: Not On Line","按钮不开门: 门不在线",
"33","Warn","Push Button Invalid: InterLock","按钮不开门: 互锁",
"34","Warn","Threat","胁迫报警",
"35","Warn","Threat Open","胁迫报警开",
"36","Warn","Threat Close","胁迫报警关",
"37","Warn","Open too long","门长时间未关报警[合法开门后]",
"38","Warn","Forced Open","强行闯入报警",
"39","Warn","Fire","火警",
"40","Warn","Forced Close","强制关门",
"41","Warn","Guard Against Theft","防盗报警",
"42","Warn","7*24Hour Zone","烟雾煤气温度报警",
"43","Warn","Emergency Call","紧急呼救报警",
"44","RemoteOpen","Remote Open Door","操作员远程开门",
"45","RemoteOpen","Remote Open Door By USB Reader","发卡器确定发出的远程开门"
        };

        string getReasonDetailChinese(int Reason) //Chinese description
        {
            if (Reason > 45)
            {
                return "";
            }
            if (Reason <= 0)
            {
                return "";
            }
            return RecordDetails[(Reason - 1) * 4 + 3]; //Chinese information
        }

        string getReasonDetailEnglish(int Reason) //English description
        {
            if (Reason > 45)
            {
                return "";
            }
            if (Reason <= 0)
            {
                return "";
            }
            return RecordDetails[(Reason - 1) * 4 + 2]; //English information
        }
        /// <summary>
        /// Basic function test
        /// </summary>
        /// <param name="ControllerIP">Controller IP address</param>
        /// <param name="controllerSN"> Controller serial number</param>
        /// <returns>Less than or equal to 0 failed, 1 means successful</returns>
        int testBasicFunction(String ControllerIP, long controllerSN)
        {
            int ret = 0;
            int success = 0;  //0 Failure, 1 Success


            //Create short packet pkt
            AccessPacketShort pkt = new AccessPacketShort();
            pkt.iDevSn = controllerSN;
            pkt.IP = ControllerIP;

            //1.4	Query the controller status[Function ID: 0x20](For real-time monitoring) **********************************************************************************
            pkt.Reset();
            pkt.functionID = 0x20;
            ret = pkt.run();

            success = 0;
            if (ret == 1)
            {
                //Read the information successfully...
                success = 1;
                log("1.4 Query controller status is successful...");

                //	  	The last recorded information		
                displayRecordInformation(pkt.recv); //2015-06-09 20:01:21

                //	other information		
                int[] doorStatus = new int[4];
                //28	No. 1 door door magnetic (0 means off, 1 said open)	1	0x00
                doorStatus[1 - 1] = pkt.recv[28];
                //29	No. 2 door door magnetic (0 means off, 1 said open)	1	0x00
                doorStatus[2 - 1] = pkt.recv[29];
                //30	No. 3 door door magnetic (0 means off, 1 said open)	1	0x00
                doorStatus[3 - 1] = pkt.recv[30];
                //31	No. 4 door door magnetic (0 means off, 1 said open)	1	0x00
                doorStatus[4 - 1] = pkt.recv[31];

                int[] pbStatus = new int[4];
                //32	No. 1 door button (0 for release, 1 for press)	1	0x00
                pbStatus[1 - 1] = pkt.recv[32];
                //33	No. 2 door button (0 for release, 1 for press)	1	0x00
                pbStatus[2 - 1] = pkt.recv[33];
                //34	No. 3 door button (0 for release, 1 for press)	1	0x00
                pbStatus[3 - 1] = pkt.recv[34];
                //35	No. 4 door button (0 for release, 1 for press)	1	0x00
                pbStatus[4 - 1] = pkt.recv[35];

                //36	Fault number
                // =0   No Fault
                // !=0, There is a fault (first reset the time, if there are problems, then to the factory maintenance)	1	
                int errCode = pkt.recv[36];

                //37	Controller current time
                //hour	1	0x21
                //38	minute	1	0x30
                //39	second	1	0x58

                //40-43	xid(serial number)	4	
                long sequenceId = 0;
                sequenceId = byteToLong(pkt.recv, 40, 4);

                //48
                //Special information 1 (based on actual use)
                //Keyboard key information 1


                //49	Relay status 1 [0 for door lock, 1 for door lock. 0000 when normal door is locked]
                int relayStatus = pkt.recv[49];
                if ((relayStatus & 0x1) > 0)
                {
                    //Door 1 unlocked
                }
                else
                {
                    //Door 1 locked
                }
                if ((relayStatus & 0x2) > 0)
                {
                    //Door 2 unlocked
                }
                else
                {
                    //Door 2 locked
                }
                if ((relayStatus & 0x4) > 0)
                {
                    //Door 3 unlocked
                }
                else
                {
                    //Door 3 locked
                }
                if ((relayStatus & 0x8) > 0)
                {
                    //Door 4 unlocked
                }
                else
                {
                    //Door 4 locked
                }

                //50	8-15bit bit of the door state [fire / forced lock door]
                //Bit0  Forced lock door
                //Bit1  Fire		
                int otherInputStatus = pkt.recv[50];
                if ((otherInputStatus & 0x1) > 0)
                {
                    //Forced lock door
                }
                if ((otherInputStatus & 0x2) > 0)
                {
                    //Fire
                }

                //51	V5.46Version support Controller current year	1	0x13
                //52	V5.46Version support Controller current month	1	0x06
                //53	V5.46Version support Controller current day 	1	0x22

                string controllerTime = "2000-01-01 00:00:00"; //Controller current time
                controllerTime = string.Format("{0:X2}{1:X2}-{2:X2}-{3:X2} {4:X2}:{5:X2}:{6:X2}",
                    0x20, pkt.recv[51], pkt.recv[52], pkt.recv[53], pkt.recv[37], pkt.recv[38], pkt.recv[39]);
            }
            else
            {
                log("1.4 Query controller status failed?????...");
                return -1;
            }

            //1.5	Read the date and time(Function ID: 0x32) **********************************************************************************
            pkt.Reset();
            pkt.functionID = 0x32;
            ret = pkt.run();
            success = 0;
            if (ret > 0)
            {

                string controllerTime = "2000-01-01 00:00:00"; //Controller current time
                controllerTime = string.Format("{0:X2}{1:X2}-{2:X2}-{3:X2} {4:X2}:{5:X2}:{6:X2}",
                    pkt.recv[8], pkt.recv[9], pkt.recv[10], pkt.recv[11], pkt.recv[12], pkt.recv[13], pkt.recv[14]);

                log("1.5 Read date and time is successful...");
                success = 1;
            }

            //1.6	Set the date and time[Function ID: 0x30] **********************************************************************************
            //Press the computer's current time to calibrate the controller .....
            pkt.Reset();
            pkt.functionID = 0x30;

            DateTime ptm = DateTime.Now;
            pkt.data[0] = (byte)GetHex((ptm.Year - ptm.Year % 100) / 100);
            pkt.data[1] = (byte)GetHex((int)((ptm.Year) % 100)); //st.GetMonth()); 
            pkt.data[2] = (byte)GetHex(ptm.Month);
            pkt.data[3] = (byte)GetHex(ptm.Day);
            pkt.data[4] = (byte)GetHex(ptm.Hour);
            pkt.data[5] = (byte)GetHex(ptm.Minute);
            pkt.data[6] = (byte)GetHex(ptm.Second);
            ret = pkt.run();
            success = 0;
            if (ret > 0)
            {
                Boolean bSame = true;
                for (int i = 0; i < 7; i++)
                {
                    if (pkt.data[i] != pkt.recv[8 + i])
                    {
                        bSame = false;
                        break;
                    }
                }
                if (bSame)
                {
                    log("1.6 Set the date and time to success...");
                    success = 1;
                }
            }

            //1.7	Gets the record for the specified index number[Function ID: 0xB0] **********************************************************************************
            //(Take the record of the quotation mark 0x00000001)
            long recordIndexToGet = 0;
            pkt.Reset();
            pkt.functionID = 0xB0;
            pkt.iDevSn = controllerSN;

            //	(special
            //If = 0, then retrieve the earliest record information
            //If = 0xffffffff to retrieve the last record of information)
            //Record the index number is normal in the order of increments, the maximum up to 0xffffff = 16,777,215 (more than 10 million.) Due to limited storage space, the controller will only retain the nearest 200,000 records.When the index number more than 200,000, The old index number of the record will be overwritten, so then query the index number of the record, the return of the record type will be 0xff, that does not exist.
            recordIndexToGet = 1;
            LongToBytes(ref pkt.data, 0, recordIndexToGet);

            ret = pkt.run();
            success = 0;
            if (ret > 0)
            {
                log("1.7 The information for the index 1 record was successful...");
                //	  	The index is information for record number 1
                displayRecordInformation(pkt.recv); //2015-06-09 20:01:21

                success = 1;
            }

            //. Send the message (take the earliest record by the index number 0x00000000) [This directive is suitable for credit card record more than 20 million environment]
            pkt.Reset();
            pkt.functionID = 0xB0;
            recordIndexToGet = 0;
            LongToBytes(ref pkt.data, 0, recordIndexToGet);

            ret = pkt.run();
            success = 0;
            if (ret > 0)
            {
                log("1.7 The information for the earliest record was successful...");
                //	  	The earliest record of a message	
                displayRecordInformation(pkt.recv); //2015-06-09 20:01:21

                success = 1;
            }

            //Send a message (take the latest one through the index 0xffffffff)
            pkt.Reset();
            pkt.functionID = 0xB0;
            recordIndexToGet = 0xffffffff;
            LongToBytes(ref pkt.data, 0, recordIndexToGet);
            ret = pkt.run();
            success = 0;
            if (ret > 0)
            {
                log("1.7 The information for the latest record was successful...");
                //	  	The latest record of the information	
                displayRecordInformation(pkt.recv); //2015-06-09 20:01:21
                success = 1;
            }

            ////1.8	Set the read index number to be read[Function ID: 0xB2] **********************************************************************************
            //pkt.Reset();
            //pkt.functionID = 0xB2;
            //// (Set to read the record index number 5)
            //int recordIndexGot = 0x5;
            //LongToBytes(ref pkt.data, 0, recordIndexGot);

            ////12	Logo (to prevent false settings) 1 0x55 [fixed]
            //LongToBytes(ref pkt.data, 4, WGPacketShort.SpecialFlag);

            //ret = pkt.run();
            //success = 0;
            //if (ret > 0)
            //{
            //    if (pkt.recv[8] == 1)
            //    {
            //        log("1.8 Set the record number that has been read successfully...");
            //        success = 1;
            //    }
            //}

            ////1.9	Gets the read index number that has been read[Function ID: 0xB4] **********************************************************************************
            //pkt.Reset();
            //pkt.functionID = 0xB4;
            //int recordIndexGotToRead = 0x0;
            //ret = pkt.run();
            //success = 0;
            //if (ret > 0)
            //{
            //    recordIndexGotToRead = (int)byteToLong(pkt.recv, 8, 4);
            //    log("1.9 Get the record number that has been read successfully...");
            //    success = 1;
            //}

            ////1.8	Set the read index number to be read[Function ID: 0xB2] **********************************************************************************
            ////Restore the extracted records, prepare for the complete extraction operation of 1.9 - in actual use, in the event of a problem to recover, the normal need to restore ...
            //pkt.Reset();
            //pkt.functionID = 0xB2;
            //// (Set to read the record index number 5)
            //int recordIndexGot = 0x0;
            //LongToBytes(ref pkt.data, 0, recordIndexGot);
            ////12	Logo (to prevent false settings) 1 0x55 [fixed]
            //LongToBytes(ref pkt.data, 4, WGPacketShort.SpecialFlag);

            //ret = pkt.run();
            //success = 0;
            //if (ret > 0)
            //{
            //    if (pkt.recv[8] == 1)
            //    {
            //        log("1.8 Set the record number that has been read successfully...");
            //        success = 1;
            //    }
            //}


            //1.9	Extract record operation
            //1. The read record index number is obtained by the 0xB4 instruction recordIndex
            //2. Get the record of the specified index number with the 0xB0 instruction Start the record from recordIndex + 1 until it is empty
            //3. Set the value of the read record index number set by the 0xB2 instruction to the last card number to be read.
            //After the above three steps, the entire extraction of records to complete the operation
            log("1.9 The extraction record operation starts...");
            pkt.Reset();
            pkt.functionID = 0xB4;
            ret = pkt.run();
            success = 0;
            if (ret > 0)
            {
                long recordIndexGotToRead = 0x0;
                recordIndexGotToRead = (long)byteToLong(pkt.recv, 8, 4);
                pkt.Reset();
                pkt.functionID = 0xB0;
                pkt.iDevSn = controllerSN;
                long recordIndexToGetStart = recordIndexGotToRead + 1;
                long recordIndexValidGet = 0;
                int cnt = 0;
                do
                {
                    if (bStopBasicFunction)
                    {
                        return 0;  //2015-06-10 09:08:14 Stop
                    }
                    LongToBytes(ref pkt.data, 0, recordIndexToGetStart);
                    ret = pkt.run();
                    success = 0;
                    if (ret > 0)
                    {
                        success = 1;

                        //12	Record type
                        //0=no record
                        //1=Credit card record
                        //2=Door, button, device start, remote door open record
                        //3=alarm record	1	
                        //0xFF=Indicates that the record of the specified index bit has been overwritten. Please use index 0 to retrieve the index value of the earliest record
                        int recordType = pkt.recv[12];
                        if (recordType == 0)
                        {
                            break; //No more records
                        }
                        if (recordType == 0xff)//This index number is invalid to reset the index value
                        {
                            //Take the index bit of the earliest record
                            pkt.Reset();
                            pkt.functionID = 0xB0;
                            recordIndexToGet = 0;
                            LongToBytes(ref pkt.data, 0, recordIndexToGet);

                            ret = pkt.run();
                            success = 0;
                            if (ret > 0)
                            {
                                log("1.7 The information for the earliest record was successful...");
                                recordIndexGotToRead = (int)byteToLong(pkt.recv, 8, 4);
                                recordIndexToGetStart = recordIndexGotToRead;
                                continue;
                            }
                            success = 0;  
                            break;
                        }
                        recordIndexValidGet = recordIndexToGetStart;

                        displayRecordInformation(pkt.recv); //2015-06-09 20:01:21

                        //.......Store the received records for storage
                        //*****
                        //###############
                    }
                    else
                    {
                        //Extraction failed
                        break;
                    }
                    recordIndexToGetStart++;
                } while (cnt++ < 200000);
                if (success > 0)
                {
                    //Set the value of the read record index number set by the 0xB2 instruction to the last card number to be read.
                    pkt.Reset();
                    pkt.functionID = 0xB2;
                    LongToBytes(ref pkt.data, 0, recordIndexValidGet);

                    //12	Logo (to prevent false settings) 1 0x55 [fixed]
                    LongToBytes(ref pkt.data, 4, AccessPacketShort.SpecialFlag);

                    ret = pkt.run();
                    success = 0;
                    if (ret > 0)
                    {
                        if (pkt.recv[8] == 1)
                        {
                            //Completely extract successfully....
                            log("1.9 Completely successful success...");
                            success = 1;
                        }
                    }

                }
            }

            //1.10	Remote open the door[Function ID: 0x40] **********************************************************************************
            int doorNO = 1;
            pkt.Reset();
            pkt.functionID = 0x40;
            pkt.data[0] = (byte)(doorNO & 0xff); //2013-11-03 20:56:33
            ret = pkt.run();
            success = 0;
            if (ret > 0)
            {
                if (pkt.recv[8] == 1)
                {
                    //有效开门.....
                    log("1.10 Remote open the door to success...");
                    success = 1;
                }
            }

            //1.11	Permission to add or modify[Function ID: 0x50] **********************************************************************************
            //Increase the card number 0D D7 37 00, through the current controller of all the doors
            pkt.Reset();
            pkt.functionID = 0x50;
            //0D D7 37 00 Card number to be added or modified Permissions = 0x0037D70D = 3659533 (decimal)
            long cardNOOfPrivilege = 0x0037D70D;
            LongToBytes(ref pkt.data, 0, cardNOOfPrivilege);

            //20 10 01 01 Start Date:  2010-01-01   (Must be greater than 2001)
            pkt.data[4] = 0x20;
            pkt.data[5] = 0x10;
            pkt.data[6] = 0x01;
            pkt.data[7] = 0x01;
            //20 29 12 31 End Date:  2029-12-31
            pkt.data[8] = 0x20;
            pkt.data[9] = 0x29;
            pkt.data[10] = 0x12;
            pkt.data[11] = 0x31;
            //01 Allows entry via door 1 [for single door, two door, four door controllers]
            pkt.data[12] = 0x01;
            //01 Allowed through the door 2 [effective for two-door, four-door controller]
            pkt.data[13] = 0x01;  //If Door 2 is disabled, it is set to 0x00
            //01 Permitted via Door 3 [valid for four-door controller]
            pkt.data[14] = 0x01;
            //01 Allowed via door 4 [effective for four-door controller]
            pkt.data[15] = 0x01;

            ret = pkt.run();
            success = 0;
            if (ret > 0)
            {
                if (pkt.recv[8] == 1)
                {
                    //Then the card number = 0x0037D70D = 3659533 (decimal) card, No. 1 door relay action.
                    log("1.11 Permissions are added or modified successfully...");
                    success = 1;
                }
            }

            //1.12	Permission Delete (Single Delete)[Function ID: 0x52] **********************************************************************************
            pkt.Reset();
            pkt.functionID = 0x52;
            pkt.iDevSn = controllerSN;
            //Permission to delete the card number 0D D7 37 00 = 0x0037D70D = 3659533 (decimal)
            long cardNOOfPrivilegeToDelete = 0x0037D70D;
            LongToBytes(ref pkt.data, 0, cardNOOfPrivilegeToDelete);

            ret = pkt.run();
            success = 0;
            if (ret > 0)
            {
                if (pkt.recv[8] == 1)
                {
                    //Then the card number = 0x0037D70D = 3659533 (decimal) card, No. 1 door relay will not move.
                    log("1.12 Permission Delete (Single Delete) Success...");
                    success = 1;
                }
            }

            //1.13	Permission is cleared(all cleared)[Function ID: 0x54] **********************************************************************************
            pkt.Reset();
            pkt.functionID = 0x54;
            pkt.iDevSn = controllerSN;
            LongToBytes(ref pkt.data, 0, AccessPacketShort.SpecialFlag);

            ret = pkt.run();
            success = 0;
            if (ret > 0)
            {
                if (pkt.recv[8] == 1)
                {
                    //At this time clear the success
                    log("1.13 Permission to clear (all cleared)...");
                    success = 1;
                }
            }

            //1.14	The total number of permissions to read[Function ID: 0x58] **********************************************************************************
            pkt.Reset();
            pkt.functionID = 0x58;
            ret = pkt.run();
            success = 0;
            if (ret > 0)
            {
                int privilegeCount = 0;
                privilegeCount = (int)byteToLong(pkt.recv, 8, 4);
                log("1.14 The total number of permissions read successfully...");

                success = 1;
            }


            //Add the query operation again 1.11	Permission to add or modify[Function ID: 0x50] **********************************************************************************
            //Increase the card number 0D D7 37 00, through the current controller of all the doors
            pkt.Reset();
            pkt.functionID = 0x50;
            //0D D7 37 00 To add or modify the permissions in the card number = 0x0037D70D = 3659533 (decimal)
            cardNOOfPrivilege = 0x0037D70D;
            LongToBytes(ref pkt.data, 0, cardNOOfPrivilege);
            //20 10 01 01 Start Date:  2010-01-01   (Must be greater than 2001)
            pkt.data[4] = 0x20;
            pkt.data[5] = 0x10;
            pkt.data[6] = 0x01;
            pkt.data[7] = 0x01;
            //20 29 12 31 End Date:  2029-12-31
            pkt.data[8] = 0x20;
            pkt.data[9] = 0x29;
            pkt.data[10] = 0x12;
            pkt.data[11] = 0x31;
            //01 Allows entry via door 1 [for single door, two door, four door controllers]
            pkt.data[12] = 0x01;
            //01 Allowed through the door 2 [effective for two-door, four-door controller]
            pkt.data[13] = 0x01;  //If Door 2 is disabled, it is set to 0x00
            //01 Permitted via door 3 [valid for four-door controller]
            pkt.data[14] = 0x01;
            //01 Allowed via door 4 [effective for four-door controller]
            pkt.data[15] = 0x01;

            ret = pkt.run();
            success = 0;
            if (ret > 0)
            {
                if (pkt.recv[8] == 1)
                {
                    //Then the card number = 0x0037D70D = 3659533 (decimal) card, No. 1 door relay action.
                    log("1.11 Permissions are added or modified successfully...");
                    success = 1;
                }
            }

            //1.15	Permission query[Function ID: 0x5A] **********************************************************************************
            pkt.Reset();
            pkt.functionID = 0x5A;
            pkt.iDevSn = controllerSN;
            // (Check card number 0D D7 37 00 permissions)
            long cardNOOfPrivilegeToQuery = 0x0037D70D;
            LongToBytes(ref pkt.data, 0, cardNOOfPrivilegeToQuery);

            ret = pkt.run();
            success = 0;
            if (ret > 0)
            {

                long cardNOOfPrivilegeToGet = 0;
                cardNOOfPrivilegeToGet = byteToLong(pkt.recv, 8, 4);
                if (cardNOOfPrivilegeToGet == 0)
                {
                    //No permission information: (card number part 0)
                    log("1.15      No permission information: (card number part 0)");
                }
                else
                {
                    //Specific authority information...
                    log("1.15     Have permission information...");
                }
                log("1.15 Permission query is successful...");
                success = 1;
            }

            //1.16  Gets the permission to specify the index number[Function ID: 0x5C] **********************************************************************************
            pkt.Reset();
            pkt.functionID = 0x5C;
            pkt.iDevSn = controllerSN;
            long QueryIndex = 1; //index number(start from 1);
            LongToBytes(ref pkt.data, 0, QueryIndex);

            ret = pkt.run();
            success = 0;
            if (ret > 0)
            {

                long cardNOOfPrivilegeToGet = 0;
                cardNOOfPrivilegeToGet = byteToLong(pkt.recv, 8, 4);
                if (4294967295 == cardNOOfPrivilegeToGet) //FFFFFFFF对应于4294967295
                {
                    log("1.16      No permission information: (Permission deleted)");
                }
                else if (cardNOOfPrivilegeToGet == 0)
                {
                    //No permission information: (card number part 0)
                    log("1.16       No permission information: (card number part is 0) - this index number does not have permission after ");
                }
                else
                {
                    //Specific authority information...
                    log("1.16      Have permission information...");
                }
                log("1.16 Gets the permission to specify the index number	 Success...");
                success = 1;
            }


            //1.17	Set door control parameters (online / delay) [Function ID: 0x80] **********************************************************************************
            pkt.Reset();
            pkt.functionID = 0x80;
            //(Set Door 2  Online and Open door delay 3 seconds)
            pkt.data[0] = 0x02; //Door 2
            pkt.data[1] = 0x03; //Door Online
            pkt.data[2] = 0x03; //Open the door delay

            ret = pkt.run();
            success = 0;
            if (ret > 0)
            {
                if (pkt.data[0] == pkt.recv[8] && pkt.data[1] == pkt.recv[9] && pkt.data[2] == pkt.recv[10])
                {
                    //On success, the return value is consistent with the setting
                    log("1.17 Set the door control parameters	 Success...");
                    success = 1;
                }
                else
                {
                    //失败
                }
            }

            //1.21	权限按从小到大顺序添加[功能号: 0x56] 适用于权限数过1000, 少于8万 **********************************************************************************
            //此功能实现 完全更新全部权限, 用户不用清空之前的权限. 只是将上传的权限顺序从第1个依次到最后一个上传完成. 如果中途中断的话, 仍以原权限为主
            //建议权限数更新超过50个, 即可使用此指令

            log("1.21	Permissions are added in ascending order[Function ID: 0x56]	Start...");
            log("       1 million permissions...");

            //To 10000 card number, for example, here is a simple sort, directly to 50001 start the 10000 card.Users need to upload the card number to be stored
            int cardCount = 10000;  //2015-06-09 20:20:20 Total number of cards
            long[] cardArray = new long[cardCount];
            for (int i = 0; i < cardCount; i++)
            {
                cardArray[i] = 50001+i;
            }

            for (int i = 0; i < cardCount; i++)
            {
                if (bStopBasicFunction)
                {
                    return 0;  //2015-06-10 09:08:14 stop
                }
                pkt.Reset();
                pkt.functionID = 0x56;

                cardNOOfPrivilege = cardArray[i];
                LongToBytes(ref pkt.data, 0, cardNOOfPrivilege);

                //Other parameters are simplified when unified, can be modified according to the different card
                //20 10 01 01 Start date:  2010-01-01   (Must be greater than 2001)
                pkt.data[4] = 0x20;
                pkt.data[5] = 0x10;
                pkt.data[6] = 0x01;
                pkt.data[7] = 0x01;
                //20 29 12 31 End date:  2029-12-31
                pkt.data[8] = 0x20;
                pkt.data[9] = 0x29;
                pkt.data[10] = 0x12;
                pkt.data[11] = 0x31;
                //01 Allows entry via door 1 [for single door, two door, four door controllers]
                pkt.data[12] = 0x01;
                //01 Allowed through the door 2 [effective for two-door, four-door controller]
                pkt.data[13] = 0x01;  //If Door 2 is disabled, it is set to 0x00
                //01 Permitted via door 3 [valid for four-door controller]
                pkt.data[14] = 0x01;
                //01 Allowed via door 4 [effective for four-door controller]
                pkt.data[15] = 0x01;

                LongToBytes(ref pkt.data, 32 - 8, cardCount); //Total number of permissions
                LongToBytes(ref pkt.data, 35 - 8, i + 1);//The index of the current privilege (from 1)

                ret = pkt.run();
                success = 0;
                if (ret > 0)
                {
                    if (pkt.recv[8] == 1)
                    {
                        success = 1;
                    }
                    if (pkt.recv[8] == 0xE1)
                    {
                        log("1.21	Permissions are added in ascending order[Function ID: 0x56]	 =0xE1 Indicates that the card number is not sorted from small to large...???");
                        success = 0;
                        break;
                    }
                }
                else
                {
                    break;
                }
            }
            if (success == 1)
            {
                log("1.21	Permissions are added in ascending order[Function ID: 0x56]	 Success...");
            }
            else
            {
                log("1.21	Permissions are added in ascending order[Function ID: 0x56]	 Failure...????");
            }
           

            //其他指令  **********************************************************************************


            // **********************************************************************************

            //结束  **********************************************************************************
            pkt.close();  //Turn off the communication
            return success;
        }

        /// <summary>
        /// Receive server setup test
        /// </summary>
        /// <param name="ControllerIP">The IP address of the controller is set</param>
        /// <param name="controllerSN">Set the controller serial number</param>
        /// <param name="watchServerIP">To set the server IP</param>
        /// <param name="watchServerPort">To set the port</param>
        /// <returns>0 Fail, 1 Success</returns>
        int testWatchingServer(string ControllerIP, long controllerSN, string watchServerIP, int watchServerPort)  //Receive server test - setup
        {
            int ret = 0;
            int success = 0;  //0 Fail, 1 Success

            AccessPacketShort pkt = new AccessPacketShort();
            pkt.iDevSn = controllerSN;
            pkt.IP = ControllerIP;

            //1.18	Set the IP and port of the receiving server [Function ID: 0x90] **********************************************************************************
            //(If you do not want the controller to send data, as long as the receiving server IP is set to 0.0.0.0)
            //The port of the receiving server: 61005
            //Send once every 5 seconds: 05
            pkt.Reset();
            pkt.functionID = 0x90;
            string[] strIP = watchServerIP.Split('.');
            if (strIP.Length == 4)
            {
                pkt.data[0] = byte.Parse(strIP[0]); 
                pkt.data[1] = byte.Parse(strIP[1]);
                pkt.data[2] = byte.Parse(strIP[2]);  
                pkt.data[3] = byte.Parse(strIP[3]);
            }
            else
            {
                return 0;
            }

            //The port of the receiving server: 61005
            pkt.data[4] = (byte)((watchServerPort & 0xff));
            pkt.data[5] = (byte)((watchServerPort >> 8) & 0xff);

            //Sent every 5 seconds: 05 (regular upload information cycle is 5 seconds [normal operation every 5 seconds to send a card immediately send a)
            pkt.data[6] = 5;

            ret = pkt.run();
            success = 0;
            if (ret > 0)
            {
                if (pkt.recv[8] == 1)
                {
                    log("1.18 Set the IP and port of the receiving server to be successful...");
                    success = 1;
                }
            }


            //1.19	Read the IP and port of the receiving server [Function ID: 0x92] **********************************************************************************
            pkt.Reset();
            pkt.functionID = 0x92;

            ret = pkt.run();
            success = 0;
            if (ret > 0)
            {
                log("1.19 Read the IP and port of the receiving server successfully...");
                success = 1;
            }
            pkt.close();
            return success;
        }


        /// <summary>
        /// Open the receiving server to receive data (Note: the firewall to allow all packets of this port through the data)
        /// </summary>
        /// <param name="watchServerIP">Receive server IP (usually the current computer IP)</param>
        /// <param name="watchServerPort">Receive server port</param>
        /// <returns>1 indicates success, otherwise it fails</returns>
        int WatchingServerRuning(string watchServerIP, int watchServerPort)
        {
            //Note: The firewall should allow all packets of this port to enter
            try
            {
                WG3000_COMM.Core.wgUdpServerCom udpserver = new WG3000_COMM.Core.wgUdpServerCom(watchServerIP, watchServerPort);

                if (!udpserver.IsWatching())
                {
                    log("Enter the receiving server to monitor the state .... failed");
                    return -1;
                }
                log("Enter the receiving server to monitor the state ....");
                long recordIndex = 0;
                int recv_cnt;
                while (!bStopWatchServer)
                {
                    recv_cnt = udpserver.receivedCount();
                    if (recv_cnt > 0)
                    {
                        byte[] buff = udpserver.getRecords();
                        if (buff[1] == 0x20) //
                        {
                            long sn;
                            long recordIndexGet;
                            sn = byteToLong(buff, 4, 4);
                            log(string.Format("Received from the controller SN = {0} Of the packet..\r\n", sn));

                            recordIndexGet = byteToLong(buff, 8, 4);

                            if (recordIndex < recordIndexGet)
                            {
                                recordIndex = recordIndexGet;
                                
                                displayRecordInformation(buff); //2015-06-09 20:01:21

                             }
                        }

                    }
                    else
                    {
                        System.Threading.Thread.Sleep(10);  //'Delay 10ms
                        Application.DoEvents();

                    }
                }
                udpserver.Close();
                return 1;
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex.ToString());
                MessageBox.Show(ex.ToString());
                // throw;
            }
            return 0;
        }

        private void Form1_Load(object sender, EventArgs e)
        {

        }



    }
}
