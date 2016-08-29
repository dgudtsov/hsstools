/*
 * EAP calculations: EAP-SIM/AKA/AKA' shared routines
 * Copyright (c) 2012-2014, Sergej Srepfler <sergej.srepfler@gmail.com>
 * Using parts of hostapd code http://w1.fi/hostapd/
 * Copyright (c) 2004-2008, Jouni Malinen <j@w1.fi>
 *
 * This software is distributed under the terms of BSD license.
 */

#include "includes.h"
#include "common.h"
#include "wpa_debug.h"
#include "eap_common.h"
#include "eap_defs.h"
#include "crypto.h"
#include "sha1_i.h"
#include "milenage.h"
#include "aes_wrap.h"

#define EAP_AKA_OP_LEN 16
#define EAP_AKA_OPC_LEN 16
#define EAP_AKA_K_LEN 16
#define EAP_AKA_SQN_LEN 6
#define EAP_AKA_AK_LEN 6
#define EAP_AKA_AMF_LEN 2
#define EAP_AKA_XRES_LEN 8
#define EAP_AKA_PRF_LEN EAP_SIM_K_ENCR_LEN+EAP_SIM_K_AUT_LEN+EAP_SIM_KEYING_DATA_LEN+EAP_EMSK_LEN
#define EAP_AKA_XMAC_LEN 8
#define EAP_AKA_MACS_LEN 8
#define EAP_AKA_MAC_LEN 16
#define EAP_AKAP_MAC_LEN 32

void fromHex(u8* hex1, char* param) {
   int i,h;
   int hexc;
   if (strncmp("0x",param,2)==0) { // hex
       for (i=2,h=0;i<=strlen(param)-2;i+=2) {
           sscanf(param+i,"%2x",&hexc);
           hex1[h++]=(u8)hexc;
       }
   }
}

void dumpToHex(char* msg, u8* buf,int buf_size) {
   int i;
   printf("%s",msg);
   for (i=0;i<buf_size;i++) {
       printf ("%02X",(u8) buf[i]);
   }
   printf("\n");
}

void * my_malloc(size_t size) {
   void * var;
   var=os_malloc(size+1);
   memset(var,0,size+1);
   return var;
}

void ComputeOPc( u8* k, u8* op, u8* opc ) {
  int i;
  
  i=aes_128_encrypt_block( k, op, opc );
  for (i=0; i<EAP_AKA_OPC_LEN; i++)
    opc[i] ^= op[i];
  return;
} /* end of function ComputeOPc */


void calc_computeOPc(char* p_op, char* p_k){
    u8 op[EAP_AKA_OP_LEN];
    u8 k[EAP_AKA_K_LEN];
    u8 opc[EAP_AKA_OPC_LEN];
    
    fromHex(op,p_op);
    fromHex(k,p_k);
    // Debugging output to confirm correct input
    dumpToHex("OP=",op,EAP_AKA_OP_LEN);
    dumpToHex("K=",k,EAP_AKA_K_LEN);
    ComputeOPc(k,op,opc);    
    dumpToHex("OPc=",opc,EAP_AKA_OPC_LEN);    
}

void calc_milenage_f1(char* p_opc, char* p_k, char* p_rand,
                      char* p_sqn, char* p_amf){
    u8 opc[EAP_AKA_OPC_LEN];
    u8 k[EAP_AKA_K_LEN];
    u8 rand[EAP_AKA_RAND_LEN];
    u8 sqn[EAP_AKA_SQN_LEN];
    u8 amf[EAP_AKA_AMF_LEN];
    u8 maca[EAP_AKA_XMAC_LEN];
    u8 macs[EAP_AKA_MACS_LEN];
    
    fromHex(opc,p_opc);
    fromHex(k,p_k);
    fromHex(rand,p_rand);
    fromHex(sqn,p_sqn);
    fromHex(amf,p_amf);
    // Debugging output to confirm correct input
    dumpToHex("OPc=",opc,EAP_AKA_OPC_LEN);
    dumpToHex("K=",k,EAP_AKA_K_LEN);
    dumpToHex("RAND=",rand,EAP_AKA_RAND_LEN);
    dumpToHex("SQN=",sqn,EAP_AKA_SQN_LEN);
    dumpToHex("AMF=",amf,EAP_AKA_AMF_LEN);
    // Now we have our input parameters
    milenage_f1(opc,k,rand,sqn,amf,maca,macs);   
    dumpToHex("XMAC=",maca,EAP_AKA_XMAC_LEN);
    dumpToHex("MACS=",macs,EAP_AKA_MACS_LEN);
}

void calc_milenage_f2345(char* p_opc,char* p_k,char* p_rand) {
    u8 opc[EAP_AKA_OPC_LEN];
    u8 k[EAP_AKA_K_LEN];
    u8 rand[EAP_AKA_RAND_LEN];
    u8 xres[EAP_AKA_XRES_LEN];
    u8 ck[EAP_AKA_CK_LEN];
    u8 ik[EAP_AKA_IK_LEN];
    u8 ak[EAP_AKA_AK_LEN];
    u8 akstar[EAP_AKA_AK_LEN];
   
    fromHex(opc,p_opc);
    fromHex(k,p_k);
    fromHex(rand,p_rand);
    // Debugging output to confirm correct input
    dumpToHex("OPc=",opc,EAP_AKA_OPC_LEN);
    dumpToHex("K=",k,EAP_AKA_K_LEN);
    dumpToHex("RAND=",rand,EAP_AKA_RAND_LEN);
    // Now we have our input parameters
    milenage_f2345(opc,k,rand,xres,ck,ik,ak,akstar);
    dumpToHex("XRES=",xres,EAP_AKA_XRES_LEN);
    dumpToHex("CK=",ck,EAP_AKA_CK_LEN);
    dumpToHex("IK=",ik,EAP_AKA_IK_LEN);
    dumpToHex("AK=",ak,EAP_AKA_AK_LEN);
    dumpToHex("AKS=",akstar,EAP_AKA_AK_LEN);
}

void calc_sim(u8* identity, char* p_kc, char* p_nonce_mt, char* p_ver_list, char* p_selected_ver) {
    u8* kc;
    u8 nonce_mt[EAP_SIM_NONCE_MT_LEN];
    u8* ver_list;
    u16 selected_ver;
    int identity_len;
    int ver_list_len;
    int kc_len;
    int nkc;
    u8 mk[EAP_SIM_MK_LEN];
    u8 kencr[EAP_SIM_K_ENCR_LEN];
    u8 kaut[EAP_SIM_K_AUT_LEN];
    u8 msk[EAP_SIM_KEYING_DATA_LEN];
    u8 emsk[EAP_EMSK_LEN];
    u8 buf[EAP_AKA_PRF_LEN];
    int skip;

    identity_len=strlen((char *)identity);
    kc_len=strlen(p_kc)/2-1;
    kc=my_malloc(kc_len);
    fromHex(kc,p_kc);
    nkc=kc_len/EAP_SIM_KC_LEN;
    fromHex(nonce_mt,p_nonce_mt);
    ver_list_len=strlen(p_ver_list)/2-1;
    ver_list=my_malloc(ver_list_len);
    fromHex(ver_list,p_ver_list);
    selected_ver=atoi(p_selected_ver);

    // Debugging output to confirm correct input
    printf("Identity=%s\n",identity);
    dumpToHex("n*KC=",kc,kc_len);
    printf("n=%d\n",nkc);
    dumpToHex("NONCE_MT=",nonce_mt,EAP_SIM_NONCE_MT_LEN);
    printf("SELECTED_VER=%d\n",selected_ver);
    dumpToHex("VER_LIST=",ver_list,ver_list_len);    
    // Now we have our input parameters
    eap_sim_derive_mk(identity, identity_len, nonce_mt, selected_ver,
       ver_list, ver_list_len, nkc, kc, mk);
    dumpToHex("MK=",mk,EAP_SIM_MK_LEN);
    eap_sim_prf(mk,buf,sizeof(buf));
    dumpToHex("PRF=",buf,EAP_AKA_PRF_LEN);
    // output of PRF is Kencr+Kaut+MSK+EMSK
    skip=0;
    os_memcpy(kencr,buf,EAP_SIM_K_ENCR_LEN);
    dumpToHex("KENCR=",kencr,EAP_SIM_K_ENCR_LEN);
    skip+=EAP_SIM_K_ENCR_LEN;
    os_memcpy(kaut,buf+skip,EAP_SIM_K_AUT_LEN);
    dumpToHex("KAUT=",kaut,EAP_SIM_K_AUT_LEN);
    skip+=EAP_SIM_K_AUT_LEN;
    os_memcpy(msk,buf+skip,EAP_SIM_KEYING_DATA_LEN);
    dumpToHex("MSK=",msk,EAP_SIM_KEYING_DATA_LEN);
    skip+=EAP_SIM_KEYING_DATA_LEN;
    os_memcpy(emsk,buf+skip,EAP_EMSK_LEN);
    dumpToHex("EMSK=",emsk,EAP_EMSK_LEN);
}

void calc_aka(char* p_identity,char* p_ck, char* p_ik) {
    char* identity;
    u8* ck;
    u8* ik;
    int identity_len;
    u8* mk;
    u8 kencr[EAP_SIM_K_ENCR_LEN];
    u8 kaut[EAP_SIM_K_AUT_LEN];
    u8 msk[EAP_SIM_KEYING_DATA_LEN];
    u8 emsk[EAP_EMSK_LEN];
    u8 buf[EAP_AKA_PRF_LEN];
    int skip;
    
    identity_len=strlen(p_identity);
    identity=my_malloc(identity_len);
    strcpy(identity,p_identity);
    ck=my_malloc(EAP_AKA_CK_LEN);
    ik=my_malloc(EAP_AKA_IK_LEN);
    fromHex(ik,p_ik);
    fromHex(ck,p_ck);
    // Debugging output to confirm correct input
    printf("Identity=%s\n",identity);
    dumpToHex("Ck=",ck,EAP_AKA_CK_LEN);
    dumpToHex("Ik=",ik,EAP_AKA_IK_LEN);
    // Now we have our input parameters
    mk=my_malloc(EAP_SIM_MK_LEN); 
    eap_aka_derive_mk((u8*)identity, identity_len,ik,ck,mk);
    dumpToHex("MK=",mk,EAP_SIM_MK_LEN);
    eap_sim_prf(mk,buf,sizeof(buf));
    dumpToHex("PRF=",buf,EAP_AKA_PRF_LEN);
    // output of PRF is Kencr+Kaut+MSK+EMSK
    skip=0;
    os_memcpy(kencr,buf,EAP_SIM_K_ENCR_LEN);
    dumpToHex("KENCR=",kencr,EAP_SIM_K_ENCR_LEN);
    skip+=EAP_SIM_K_ENCR_LEN;
    os_memcpy(kaut,buf+skip,EAP_SIM_K_AUT_LEN);
    dumpToHex("KAUT=",kaut,EAP_SIM_K_AUT_LEN);
    skip+=EAP_SIM_K_AUT_LEN;
    os_memcpy(msk,buf+skip,EAP_SIM_KEYING_DATA_LEN);
    dumpToHex("MSK=",msk,EAP_SIM_KEYING_DATA_LEN);
    skip+=EAP_SIM_KEYING_DATA_LEN;
    os_memcpy(emsk,buf+skip,EAP_EMSK_LEN);
    dumpToHex("EMSK=",emsk,EAP_EMSK_LEN);
}

void calc_akaprime(char* p_identity, char* p_ck, char* p_ik) {
    char* identity;
    u8* ck;
    u8* ik;
    int identity_len;
    u8* kencr;
    u8* kaut;
    u8* kre;
    u8* msk;
    u8* emsk;
    
    identity_len=strlen(p_identity);
    identity=my_malloc(identity_len);
    ck=my_malloc(EAP_AKA_CK_LEN);
    ik=my_malloc(EAP_AKA_IK_LEN);
    kencr=my_malloc(EAP_SIM_K_ENCR_LEN);
    kaut=my_malloc(EAP_AKA_PRIME_K_AUT_LEN);
    kre=my_malloc(EAP_AKA_PRIME_K_RE_LEN);
    msk=my_malloc(EAP_MSK_LEN);
    emsk=my_malloc(EAP_EMSK_LEN);
    strcpy(identity,p_identity);
    fromHex(ik,p_ik);
    fromHex(ck,p_ck);
    // Debugging output to confirm correct input
    printf("Identity=%s\n",identity);
    dumpToHex("Ck=",ck,EAP_AKA_CK_LEN);
    dumpToHex("Ik=",ik,EAP_AKA_IK_LEN);
    // Now we have our input parameters
    eap_aka_prime_derive_keys((u8*)identity, identity_len, ik, ck,
                               kencr, kaut, kre,  msk, emsk);
    dumpToHex("KENCR=",kencr,EAP_SIM_K_ENCR_LEN);
    dumpToHex("KAUT=",kaut,EAP_AKA_PRIME_K_AUT_LEN);
    dumpToHex("KRE=",kre,EAP_AKA_PRIME_K_RE_LEN);
    dumpToHex("MSK=",msk,EAP_MSK_LEN);
    dumpToHex("EMSK=",emsk,EAP_EMSK_LEN);
}

void calc_mac_sim(char* p_kaut,char* p_msg,char* p_data) {
    u8* msg;
    u8* k_aut;
    int msg_len;
    u8* extra;
    int extra_len;
    u8* mac;
    
    msg_len=strlen(p_msg)/2-1;
    msg=my_malloc(msg_len);
    k_aut=my_malloc(EAP_SIM_K_AUT_LEN);
    fromHex(msg,p_msg);
    fromHex(k_aut,p_kaut);
    if (p_data!=NULL) {
        extra_len=strlen(p_data)/2-1;
        extra=my_malloc(extra_len);
        fromHex(extra,p_data);         
        printf("Data included %d\n",extra_len);
    }
    else {
        extra_len=0;
        extra=my_malloc(1);
    }    
    // Debugging output to confirm correct input
    dumpToHex("Kaut=",k_aut,EAP_SIM_K_AUT_LEN);
    dumpToHex("Msg=",msg,msg_len);
    dumpToHex("Data=",extra,extra_len);    
    // Now we have our input parameters
    mac=my_malloc(EAP_AKAP_MAC_LEN);
    eap_sim_add_mac(k_aut,msg,msg_len,mac,extra,extra_len);
    dumpToHex("MAC=",mac,EAP_AKA_MAC_LEN);
}

void calc_mac_aka(char* p_kaut,char* p_msg,char* p_data) {
    u8* msg;
    u8* k_aut;
    int msg_len;
    u8* extra;
    int extra_len;
    u8* mac;
    
    msg_len=strlen(p_msg)/2-1;
    msg=my_malloc(msg_len);
    k_aut=my_malloc(EAP_SIM_K_AUT_LEN);
    fromHex(msg,p_msg);
    fromHex(k_aut,p_kaut);
    if (p_data!=NULL) {
        extra_len=strlen(p_data)/2-1;
        extra=my_malloc(extra_len);
        fromHex(extra,p_data);   
        printf("Data included %d\n",extra_len);        
    }
    else {
        extra_len=0;
        extra=my_malloc(1);
    }    
    // Debugging output to confirm correct input
    dumpToHex("Kaut=",k_aut,EAP_SIM_K_AUT_LEN);
    dumpToHex("Msg=",msg,msg_len);
    dumpToHex("Data=",extra,extra_len);    
    // Now we have our input parameters
    mac=my_malloc(EAP_AKAP_MAC_LEN);
    eap_sim_add_mac(k_aut,msg,msg_len,mac,extra,extra_len);
    dumpToHex("MAC=",mac,EAP_AKA_MAC_LEN);
}

void calc_mac_akaprime(char* p_kaut,char* p_msg,char* p_data) {
    u8* msg;
    u8* k_aut;
    int msg_len;
    u8* extra;
    int extra_len;
    u8* mac;
    
    msg_len=strlen(p_msg)/2-1;
    msg=my_malloc(msg_len);
    k_aut=my_malloc(EAP_AKA_PRIME_K_AUT_LEN);
    fromHex(msg,p_msg);
    fromHex(k_aut,p_kaut);
    if (p_data!=NULL) {
        extra_len=strlen(p_data)/2-1;
        extra=my_malloc(extra_len);
        fromHex(extra,p_data);         
        printf("Data included %d\n",extra_len);
    }
    else {
        extra_len=0;
        extra=my_malloc(1);
    }    
    // Debugging output to confirm correct input
    dumpToHex("Kaut=",k_aut,EAP_AKA_PRIME_K_AUT_LEN);
    dumpToHex("Msg=",msg,msg_len);
    dumpToHex("Data=",extra,extra_len);
    // Now we have our input parameters
    mac=my_malloc(EAP_AKAP_MAC_LEN);
    eap_sim_add_mac_sha256(k_aut,msg,msg_len,mac,extra,extra_len);
    dumpToHex("MAC=",mac,EAP_AKA_MAC_LEN);
}

void calc_encrypt(char* p_kencr, char* p_iv, char* p_msg) {
    u8* k_encr;
    u8* data;
    u8* iv;
    int iv_len;
    int k_encr_len;
    int data_len;
    int ret;

    iv_len=strlen(p_iv)/2-1;
    k_encr_len=strlen(p_kencr)/2-1;
    data_len=strlen(p_msg)/2-1;

    iv=my_malloc(iv_len);
    k_encr=my_malloc(k_encr_len);
    data=my_malloc(data_len);
    fromHex(iv,p_iv);
    fromHex(k_encr,p_kencr);
    fromHex(data,p_msg);
    // Debugging output to confirm correct input
    dumpToHex("IV=",iv,iv_len);
    dumpToHex("Kencr=",k_encr,k_encr_len);
    dumpToHex("InMsg=",data,data_len);    
    // Now we have our input parameters
    ret=aes_128_cbc_encrypt(k_encr, iv, data, data_len);
    dumpToHex("ENCRYPTED=",data,data_len);
    if (ret!=0) {
        printf("ERROR=AES-128-CBC-ENCRYPT\n");
    }
}

void calc_decrypt(char* p_kencr, char* p_iv, char* p_msg) {
    u8* decrypted;
    u8* k_encr;
    u8* encr_data;
    u8* iv;
    int encr_data_len;
    int iv_len;
    int k_encr_len;
    int ret;
    
    iv_len=strlen(p_iv)/2-1;
    k_encr_len=strlen(p_kencr)/2-1;
    encr_data_len=strlen(p_msg)/2-1;
    iv=my_malloc(iv_len);
    k_encr=my_malloc(k_encr_len);
    encr_data=my_malloc(encr_data_len);
    decrypted=my_malloc(encr_data_len);
    fromHex(iv,p_iv);
    fromHex(k_encr,p_kencr);
    fromHex(encr_data,p_msg);
    // Debugging output to confirm correct input
    dumpToHex("IV=",iv,iv_len);
    dumpToHex("Kencr=",k_encr,k_encr_len);
    dumpToHex("InMsg=",encr_data,encr_data_len);
    // Now we have our input parameters
    os_memcpy(decrypted,encr_data,encr_data_len);
    ret=aes_128_cbc_decrypt(k_encr, iv, decrypted, encr_data_len);
    dumpToHex("DECRYPTED=",decrypted,encr_data_len);
    if (ret!=0) {
        printf("ERROR=AES-128-CBC-DECRYPT\n");
    }
}

int main(int argc, char *argv[]) {
    // main switch 
    if (argc > 1) {
        if (strcmp(argv[1],"sim")==0) { //SIM key calculation
            // in:identity, n*kc, nonce_mt, ver_list, selected_ver
            // out: keys
            calc_sim((u8*)argv[2],argv[3],argv[4],argv[5],argv[6]);
        }
        if (strcmp(argv[1],"aka")==0) { //AKA key calculation
            // in:Identity,Ck,Ik
            // out: keys
            calc_aka(argv[2],argv[3],argv[4]);
        }
        if (strcmp(argv[1],"akaprime")==0) { //AKAPrime key calculation
            // in:Identity,Ck,Ik
            // out: keys
            calc_akaprime(argv[2],argv[3],argv[4]);
        }
        if (strcmp(argv[1],"mac-sim")==0) { //HMAC sim-sha1 calculation
           // in: k_aut,msg,data
            // out: hmac-sha1
            if (argc==5) { calc_mac_sim(argv[2],argv[3],argv[4]); }
            else { calc_mac_sim(argv[2],argv[3], NULL); }
        }
        if (strcmp(argv[1],"mac-aka")==0) { //HMAC sha1 calculation
            // in: k_aut,msg,data
            // out: hmac-sha1
            if (argc==5) { calc_mac_aka(argv[2],argv[3],argv[4]); }
            else { calc_mac_aka(argv[2],argv[3], NULL); }            
        }
        if (strcmp(argv[1],"mac-akaprime")==0) { //HMAC sha256 calculation
            // in: k_aut,msg,data
            // out: hmac-sha256
            if (argc==5) { calc_mac_akaprime(argv[2],argv[3],argv[4]); }
            else { calc_mac_akaprime(argv[2],argv[3], NULL); }            
        }
        if (strcmp(argv[1],"milenage-f2345")==0) { //milenage f2345
            // in: OP,K,RAND
            // out: XRES,CK,IK,AK
            calc_milenage_f2345(argv[2],argv[3],argv[4]);
        }
        if (strcmp(argv[1],"milenage-f1")==0) { //milenage f1+f1*
            // in: OP,K,RAND,SQN,AMF
            // out: MAC_A(XMAC),MAC_S,AK*
            calc_milenage_f1(argv[2],argv[3],argv[4],argv[5],argv[6]);
        }
        if (strcmp(argv[1],"computeOPc")==0) { //compute OPc
            // in: OP,K
            // out: OPc
            calc_computeOPc(argv[2],argv[3]);
        }
        if (strcmp(argv[1],"encrypt")==0) { //aes_128_cbc
            // in: IV, K_encr, msg
            // out: encoded msg
            calc_encrypt(argv[3],argv[2],argv[4]);
        }
        if (strcmp(argv[1],"decrypt")==0) { //aes_128_cbc
            // in: IV, K_encr, msg
            // out: decoded msg
            calc_decrypt(argv[3],argv[2],argv[4]);
        }
    }
    else {
        printf("EAP calculator V 0.3.2 Copyright (c) 2012-2014 by Sergej Srepfler\n");
        printf("Using parts of hostapd Copyright (c) 2004-2008, Jouni Malinen and contributors\n");
        printf("\ncommands are\n");
        printf("sim <Identity> <0xn*Kc> <0xNONCE_MT> <0xVER_LIST> <selected_ver>\n");
        printf("aka <Identity> <0xCk> <0xIk>\n");
        printf("akaprime <Identity> <0xCk> <0xIk>\n");
        printf("mac-sim <0xK_aut> <0xMSG> [0xDATA]\n");
        printf("mac-aka <0xK_aut> <0xMSG> [0xDATA]\n");
        printf("mac-akaprime <0xK_aut> <0xMSG> [0xDATA]\n");
        printf("computeOPc <0xOP> <0xK>\n");
        printf("milenage-f1 <0xOPc> <0xK> <0xRAND> <0xSQN> <0xAMF>\n");
        printf("milenage-f2345 <0xOPc> <0xK> <0xRAND>\n");
        printf("encrypt <0xIV> <0xK_encr> <0xMSG>\n");
        printf("decrypt <0xIV> <0xK_encr> <0xMSG>\n");
    }
    return 0;
}

/*
#####################################################        
# History
# 0.3
# 0.3.2 - Mar 01 '14 - computeOPc separated, renamed encode/decode to encrypt/decrypt
#                    - fixed param passing for MAC calculation (when NONCE_S is used for AKA)
#                    NOTE: BREAKING COMPATIBILITY due to extending number of params
*/