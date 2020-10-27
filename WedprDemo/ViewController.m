// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

#import "ViewController.h"
#import "wedpr_crypto.h"
#import "wedpr_vcl.h"
#import "Vcl.pbobjc.h"
#import "Common.pbobjc.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    vclDemo(2,2,4);
    cryptoDemo();

}

void vclDemo(unsigned long(c1Value), unsigned long(c2Value), unsigned long(c3Value)) {
    printf("\n*******\nVCL PROOF RUN\n*******\n");
    NSError *error;

    // Makes a confidential credit record and owner secret for c1Value.
    NSString *c1ResultStr = @(*wedpr_vcl_makeCredit(c1Value));
    if(c1ResultStr.length == 0) {
        printf("interface调用错误");
        return ;
    }

    // Encodes string to bytes.
    NSData *decodedData = [[NSData alloc] initWithBase64EncodedString:c1ResultStr options:0];
    VclResult *c1Result = [VclResult parseFromData:decodedData error:&error];

    // Makes a confidential credit record and owner secret for c2Value.
    NSString *c2ResultStr = @(*wedpr_vcl_makeCredit(c2Value));
    decodedData = [[NSData alloc] initWithBase64EncodedString:c2ResultStr options:0];
    VclResult *c2Result = [VclResult parseFromData:decodedData error:&error];

    // Makes a confidential credit record and owner secret for c3Value.
    NSString *c3ResultStr = @(*wedpr_vcl_makeCredit(c3Value));
    decodedData = [[NSData alloc] initWithBase64EncodedString:c3ResultStr options:0];
    VclResult *c3Result = [VclResult parseFromData:decodedData error:&error];

    // Proves three confidential credit records(c1Result, c2Result, c3Result)
    // satisfying a sum relationship, i.e. the values embedded in them
    // satisfying c1Value + c2Value = c3Value.
    NSString *sumProofStr = @(*wedpr_vcl_proveSumBalance([c1Result.secret UTF8String], [c2Result.secret UTF8String], [c3Result.secret UTF8String]));

    // Verifies whether three confidential credit records(c1Result, c2Result, c3Result)
    // satisfying a sum relationship, i.e. the values embedded in them
    // satisfying c1Value + c2Value = c3Value.
    int result = wedpr_vcl_verifySumBalance([c1Result.credit UTF8String], [c2Result.credit UTF8String], [c3Result.credit UTF8String], [sumProofStr UTF8String]);

    // Proves three confidential credit records(c1Result, c2Result, c3Result)
    // satisfying a product relationship, i.e. the values embedded in them
    // satisfying c1Value * c2Value = c3Value.
    NSString *productProofStr = @(*wedpr_vcl_proveProductBalance([c1Result.secret UTF8String], [c2Result.secret UTF8String], [c3Result.secret UTF8String]));

    // Verifies whether three confidential credit records(c1Result, c2Result, c3Result)
    // satisfying a product relationship, i.e. the values embedded in them
    // satisfying c1Value * c2Value = c3Value.
    result = wedpr_vcl_verifyProductBalance([c1Result.credit UTF8String], [c2Result.credit UTF8String], [c3Result.credit UTF8String], [productProofStr UTF8String]);

    // Proves whether the value(c1Value) embedded in a confidential credit record(c1Result)
    // belongs to (0, 2^RANGE_SIZE_IN_BITS - 1].
    // RANGE_SIZE_IN_BITS is defined in the dynamic library of VCL, whose typical value is 32.
    NSString *rangeProofStr = @(*wedpr_vcl_proveRange([c1Result.secret UTF8String]));

    // Verifies whether the value(c1Value) embedded in a confidential credit record(c1Result)
    // belongs to (0, 2^RANGE_SIZE_IN_BITS - 1].
    // RANGE_SIZE_IN_BITS is defined in the dynamic library of VCL, whose typical value is 32.
    result = wedpr_vcl_verifyRange([c1Result.credit UTF8String], [rangeProofStr UTF8String]);
}

void cryptoDemo() {
    printf("\n*******\nWeDPR CRYPTO RUN\n*******\n");
    NSError *error;
    // Generate EC keyPair;
    NSString *keyPairStr = @(*wedpr_secp256k1_gen_key_pair());
    if(keyPairStr.length == 0) {
        printf("interface调用错误");
        return ;
    }
    NSData *decodedData = [[NSData alloc] initWithBase64EncodedString:keyPairStr options:0];
    Keypair *keyPair = [Keypair parseFromData:decodedData error:&error];
    printf("public key = :%s",keyPair.publicKey);
    printf("privateKey key = :%s",keyPair.privateKey);

    NSString *message = keyPair.publicKey;
    // Hash message with keccak256";
    NSString *hashStr = @(*wedpr_keccak256_hash([message UTF8String]));
    printf("messageHash = :%s",hashStr);

    // Sign message with ECDSA by curve secp256k1";
    NSString *signatureStr = @(*wedpr_secp256k1_sign([keyPair.privateKey UTF8String], [hashStr UTF8String]));
    printf("signatureStr = :%s",signatureStr);

    // Verify message with signature";
    int result = wedpr_secp256k1_verify([keyPair.publicKey UTF8String], [hashStr UTF8String], [signatureStr UTF8String]);
    printf("result = :%s",result);

    // Encrypt message with ECIES by curve secp256k1";
    NSString *cipherData = @(*wedpr_secp256k1_ecies_encrypt([keyPair.publicKey UTF8String], [hashStr UTF8String]));
    printf("cipherData = :%s",cipherData);

    // Decrypt message with ECIES by curve secp256k1";
    NSString *plainData = @(*wedpr_secp256k1_ecies_decrypt([keyPair.privateKey UTF8String], [cipherData UTF8String]));
    printf("plainData = :%s",plainData);
}

@end
