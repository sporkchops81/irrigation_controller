//-------------------------------------------------
// Sporkchops81 - January 2014
//-------------------------------------------------
//
// pin 4,5,6,7: relays
// pin A0 : input button
//
// usage: 
//   - input button cycles through relays
//   - web interface
//   - relays are turned off by safety timer
//-------------------------------------------------

#include "etherShield.h"
#include "TimerOne.h"

//#define WATER_DBG

// please modify the following two lines. mac and ip have to be unique on your LAN.
static uint8_t mymac[6] = {0x54,0x55,0x58,0x10,0x00,0x24}; 
static uint8_t myip[4] = {192,168,1,6};
static char baseurl[] = "http://192.168.1.203/";
static uint16_t mywwwport = 80; // listen port for tcp/www (max range 1-254)

#define NUM_SWITCH 3 // # of controlled circuits
int LED_PIN[NUM_SWITCH] = {4,5,6}; // {4,5,6,7};
#define MAX_TIME 60*60 // safety timer in seconds

#define BUFFER_SIZE 1000
static uint8_t buf[BUFFER_SIZE+1];
#define STR_BUFFER_SIZE 22
static char strbuf[STR_BUFFER_SIZE+1];

EtherShield es=EtherShield();

byte on_off[NUM_SWITCH];
int analogInPin = 14; // A0
int analogInGnd = 15; // A1
int analogInVcc = 16; // A2
int analogPin = 0;

// prepare the webpage by writing the data to the tcp send buffer
uint16_t print_webpage(uint8_t *buf, byte* on_off);
int8_t analyse_cmd(char *str);

// timer --------------------------
int seconds = 0;
 
void callback()
{
  char bufd[128];
  sprintf(bufd, "seconds: %d", seconds);
  Serial.println(bufd);

  if (seconds == 1)
    {
    // turn everything off
    sprintf(bufd, "turn everything off");
    Serial.println(bufd);
    int swi;
    for(swi=0; swi<NUM_SWITCH; swi++)
      {
      on_off[swi] = LOW;
      digitalWrite(LED_PIN[swi], on_off[swi]);
      }
    }

  if (seconds)
    seconds--;
}

// end of timer -------------------
 
void setup()
{
  // default state is OFF
  int i;
  for(i=0; i<NUM_SWITCH; i++)
    on_off[i] = LOW;
    
  Timer1.initialize(1000000);        // initialize timer1, 1 second period
  Timer1.attachInterrupt(callback);  // attaches callback() as a timer overflow interrupt

  // manual control
  pinMode(analogInPin, INPUT);
  digitalWrite(analogInPin, HIGH); // turn on pull-up resistor
  pinMode(analogInGnd, OUTPUT);
  digitalWrite(analogInGnd, LOW);
  pinMode(analogInVcc, OUTPUT);
  digitalWrite(analogInVcc, HIGH);

  // this code comes from an ethershield example -------------------
  /*initialize enc28j60*/
  es.ES_enc28j60Init(mymac);
  es.ES_enc28j60clkout(2); // change clkout from 6.25MHz to 12.5MHz
  delay(10);
  /* Magjack leds configuration, see enc28j60 datasheet, page 11 */
  // LEDA=greed LEDB=yellow
  // 0x880 is PHLCON LEDB=on, LEDA=on
  // enc28j60PhyWrite(PHLCON,0b0000 1000 1000 00 00);
  es.ES_enc28j60PhyWrite(PHLCON,0x880);
  delay(500);
  //
  // 0x990 is PHLCON LEDB=off, LEDA=off
  // enc28j60PhyWrite(PHLCON,0b0000 1001 1001 00 00);
  es.ES_enc28j60PhyWrite(PHLCON,0x990);
  delay(500);
  //
  // 0x880 is PHLCON LEDB=on, LEDA=on
  // enc28j60PhyWrite(PHLCON,0b0000 1000 1000 00 00);
  es.ES_enc28j60PhyWrite(PHLCON,0x880);
  delay(500);
  //
  // 0x990 is PHLCON LEDB=off, LEDA=off
  // enc28j60PhyWrite(PHLCON,0b0000 1001 1001 00 00);
  es.ES_enc28j60PhyWrite(PHLCON,0x990);
  delay(500);
  //
  // 0x476 is PHLCON LEDA=links status, LEDB=receive/transmit
  // enc28j60PhyWrite(PHLCON,0b0000 0100 0111 01 10);
  es.ES_enc28j60PhyWrite(PHLCON,0x476);
  delay(100);
  //init the ethernet/ip layer:
  es.ES_init_ip_arp_udp_tcp(mymac,myip,80);
  // end of example code -------------------------------------------

  int swi;
  for(swi=0;swi<NUM_SWITCH;swi++)
    {
    pinMode(LED_PIN[swi], OUTPUT); 
    digitalWrite(LED_PIN[swi], on_off[swi]);
    }

#ifdef WATER_DBG
  Serial.begin(9600); 
#endif
}

void loop(){
  
  if (millis() < 2000)
    return; // wait 2 seconds to let analog pins settle.
  
  // manual control
  int val = analogRead(analogPin);
  int mval = map(val,0,800,0,1);
  
#ifdef WATER_DBG
  char bufd[128];
  sprintf(bufd, "mval:%d (%d)", mval, val);
  Serial.println(bufd);
#endif

  if (!mval) // button was pressed
    {
    seconds = MAX_TIME;
    // cycle through circuits
    int swi, was_on = -1;
    for(swi=0; swi<NUM_SWITCH; swi++)
      {
      if (on_off[swi]==HIGH)
        was_on = swi;
      on_off[swi]=LOW;
      }
    if (++was_on < NUM_SWITCH)
      on_off[was_on]=HIGH;
    for(swi=0; swi<NUM_SWITCH; swi++)
      digitalWrite(LED_PIN[swi], on_off[swi]);
    delay(500); // cheap de-bounce
    return;
    }
  // end manual control

  // this code comes from an ethershield example -------------------
  uint16_t plen, dat_p;
  int8_t cmd;
  char buft[64];
  char dbg[64];
  plen = es.ES_enc28j60PacketReceive(BUFFER_SIZE, buf);
  /*plen will ne unequal to zero if there is a valid packet (without crc error) */
  if(plen!=0){
    // arp is broadcast if unknown but a host may also verify the mac address by sending it to a unicast address.
    if(es.ES_eth_type_is_arp_and_my_ip(buf,plen)){
      es.ES_make_arp_answer_from_request(buf);
      return;
    }
    // check if ip packets are for us:
    if(es.ES_eth_type_is_ip_and_my_ip(buf,plen)==0){
      return;
    }
    if(buf[IP_PROTO_P]==IP_PROTO_ICMP_V && buf[ICMP_TYPE_P]==ICMP_TYPE_ECHOREQUEST_V){
      es.ES_make_echo_reply_from_request(buf,plen);
      return;
    }
    // tcp port www start, compare only the lower byte
    if (buf[IP_PROTO_P]==IP_PROTO_TCP_V&&buf[TCP_DST_PORT_H_P]==0&&buf[TCP_DST_PORT_L_P]==mywwwport){
      if (buf[TCP_FLAGS_P] & TCP_FLAGS_SYN_V){
         es.ES_make_tcp_synack_from_syn(buf); // make_tcp_synack_from_syn does already send the syn,ack
         return;     
      }
      if (buf[TCP_FLAGS_P] & TCP_FLAGS_ACK_V){
        es.ES_init_len_info(buf); // init some data structures
        dat_p=es.ES_get_tcp_data_pointer();
        if (dat_p==0){ // we can possibly have no data, just ack:
          if (buf[TCP_FLAGS_P] & TCP_FLAGS_FIN_V){
            es.ES_make_tcp_ack_from_any(buf);
          }
          return;
        }
        if (strncmp("GET ",(char *)&(buf[dat_p]),4)!=0){
          // head, post and other methods for possible status codes see:
          // http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html
          plen=es.ES_fill_tcp_data_p(buf,0,PSTR("HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>200 OK</h1>"));
          goto SENDTCP;
        }
 	if (strncmp("/ ",(char *)&(buf[dat_p+4]),2)==0){
          plen=print_webpage(buf, on_off);
          goto SENDTCP;
        }
  // end of example code -------------------------------------------

        cmd=analyse_cmd((char *)&(buf[dat_p+5]));
        if (cmd != -1){
          // work out a cmd (2 or 3) and a switch number (0,1,2)
          int ncmd = 2 + ((cmd - 2) % 2); // 2->2 3->3 4->2 5->3 6->2 7->3
          int swi = (cmd - 2) / 2; // 2,3->0 4,5->1 6,7->2
          if (ncmd==2)
            on_off[swi]=HIGH;
          else if (ncmd==3)
            on_off[swi]=LOW;
          seconds = MAX_TIME;
          digitalWrite(LED_PIN[swi], on_off[swi]);  // switch on LED
#ifdef WATER_DBG
          sprintf(buft, "ncmd %d swi %d", ncmd, swi); Serial.println(buft);
#endif
        }
      }

  // this code comes from an ethershield example -------------------
REFRESHPAGE:
          plen=print_webpage(buf, on_off);

SENDTCP:  es.ES_make_tcp_ack_from_any(buf); // send ack for http get
          es.ES_make_tcp_ack_with_data(buf,plen); // send data       
      }
    }
  }

// The returned value is stored in the global var strbuf
uint8_t find_key_val(char *str,char *key)
{
        uint8_t found=0;
        uint8_t i=0;
        char *kp;
        kp=key;
        while(*str &&  *str!=' ' && found==0){
                if (*str == *kp){
                        kp++;
                        if (*kp == '\0'){
                                str++;
                                kp=key;
                                if (*str == '='){
                                        found=1;
                                }
                        }
                }else{
                        kp=key;
                }
                str++;
        }
        if (found==1){
                // copy the value to a buffer and terminate it with '\0'
                while(*str &&  *str!=' ' && *str!='&' && i<STR_BUFFER_SIZE){
                        strbuf[i]=*str;
                        i++;
                        str++;
                }
                strbuf[i]='\0';
        }
        return(found);
}

int8_t analyse_cmd(char *str)
{
        int8_t r=-1;
     
        if (find_key_val(str,"cmd")){
                if (*strbuf < 0x3a && *strbuf > 0x2f){
                        // is a ASCII number, return it
                        r=(*strbuf-0x30);
                }
        }
        return r;
}

// Add the string str to the buffer one character at a time
int add_string(uint8_t*& Buf, char* str, uint16_t &plen)
{
 int i = 0;
 
 //Loop through each char
 while (str[i]) {
   // Add each char one by one to the buffer
   Buf[TCP_CHECKSUM_L_P + 3 + plen] = str[i];
   i++;
   plen++;
 }
}

// end of example code -------------------------------------------

uint16_t print_webpage(uint8_t *buf, byte* on_off)
{
        uint16_t plen;
        char txt[128];
        plen=es.ES_fill_tcp_data_p(buf,0,PSTR("HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n"));
         
        int swi;
        plen=es.ES_fill_tcp_data_p(buf,plen,PSTR("<table border=1><tr>"));
        for(swi=0; swi<NUM_SWITCH; swi++){
          plen=es.ES_fill_tcp_data_p(buf,plen,PSTR("<td>"));
          plen=es.ES_fill_tcp_data_p(buf,plen,PSTR("<form METHOD=get action=\""));
          plen=es.ES_fill_tcp_data(buf,plen,baseurl);
          plen=es.ES_fill_tcp_data_p(buf,plen,PSTR("\">"));
          sprintf(txt, "<h2> Circuit #%d is </h2> ", swi+1); add_string(buf, txt, plen);
          if(on_off[swi] == HIGH){
            plen=es.ES_fill_tcp_data_p(buf,plen,PSTR("<h1><font color=\"#00FF00\"> "));
            plen=es.ES_fill_tcp_data_p(buf,plen,PSTR("ON"));
          } else { 
            plen=es.ES_fill_tcp_data_p(buf,plen,PSTR("<h1><font color=\"#FF0000\"> "));
            plen=es.ES_fill_tcp_data_p(buf,plen,PSTR("OFF"));
          }
          plen=es.ES_fill_tcp_data_p(buf,plen,PSTR("  </font></h1><br> ") );
          if(on_off[swi] == HIGH){
            sprintf(txt, "<input type=hidden name=cmd value=%d>", 3 + swi * 2); add_string(buf, txt, plen);     
            plen=es.ES_fill_tcp_data_p(buf,plen,PSTR("<input type=submit value=\"Switch off\"></form>"));
          } else {
            sprintf(txt, "<input type=hidden name=cmd value=%d>", 2 + swi * 2); add_string(buf, txt, plen);     
            plen=es.ES_fill_tcp_data_p(buf,plen,PSTR("<input type=submit value=\"Switch on\"></form>"));
          }
          plen=es.ES_fill_tcp_data_p(buf,plen,PSTR("</td>"));
        }
        plen=es.ES_fill_tcp_data_p(buf,plen,PSTR("</tr></table>"));

        if (plen >= BUFFER_SIZE)
          {
          plen=es.ES_fill_tcp_data_p(buf,0,PSTR("HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n"));
          plen=es.ES_fill_tcp_data_p(buf,plen,PSTR("<center><p><h1>Welcome to Arduino Ethernet Shield V1.0  </h1></p> "));
          plen=es.ES_fill_tcp_data_p(buf,plen,PSTR("<p><h1>Error: buffer is too small...</h1></p> "));
          }

        return(plen);
}
