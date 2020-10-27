// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

#import "ViewController.h"
#import "Wedpr/WedprCommon.h"
#import "Wedpr/WedprCrypto.h"
#import "Wedpr/WedprVcl.h"
// TODO: try to move this to protos folder
#import "Common.pbobjc.h"
#import "Vcl.pbobjc.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Test your demo code here.
    vclDemo(2,2,4);
//    cryptoDemo();

}

void vclDemo(unsigned long(c1Value), unsigned long(c2Value), unsigned long(c3Value)) {
    printf("\n*******\nVCL PROOF RUN\n*******\n");
    NSError *error;

    // Makes a confidential credit record and owner secret for c1Value.
    NSString *c1ResultStr = @(*wedpr_vcl_make_credit(c1Value));
    if(c1ResultStr.length == 0) {
        // The above API call should not fail.
        printf("API loading error");
        return;
    }

    // Encodes string to bytes.
    NSData *decodedData = [[NSData alloc] initWithBase64EncodedString:c1ResultStr options:0];
    VclResult *c1Result = [VclResult parseFromData:decodedData error:&error];

    // Makes a confidential credit record and owner secret for c2Value.
    NSString *c2ResultStr = @(*wedpr_vcl_make_credit(c2Value));
    decodedData = [[NSData alloc] initWithBase64EncodedString:c2ResultStr options:0];
    VclResult *c2Result = [VclResult parseFromData:decodedData error:&error];

    // Makes a confidential credit record and owner secret for c3Value.
    NSString *c3ResultStr = @(*wedpr_vcl_make_credit(c3Value));
    decodedData = [[NSData alloc] initWithBase64EncodedString:c3ResultStr options:0];
    VclResult *c3Result = [VclResult parseFromData:decodedData error:&error];

    // Proves three confidential credit records(c1Result, c2Result, c3Result)
    // satisfying a sum relationship, i.e. the values embedded in them
    // satisfying c1Value + c2Value = c3Value.
    NSString *sumProofStr = @(*wedpr_vcl_prove_sum_balance([c1Result.secret UTF8String], [c2Result.secret UTF8String], [c3Result.secret UTF8String]));

    // Verifies whether three confidential credit records(c1Result, c2Result, c3Result)
    // satisfying a sum relationship, i.e. the values embedded in them
    // satisfying c1Value + c2Value = c3Value.
    int result = wedpr_vcl_verify_sum_balance([c1Result.credit UTF8String], [c2Result.credit UTF8String], [c3Result.credit UTF8String], [sumProofStr UTF8String]);

    // Proves three confidential credit records(c1Result, c2Result, c3Result)
    // satisfying a product relationship, i.e. the values embedded in them
    // satisfying c1Value * c2Value = c3Value.
    NSString *productProofStr = @(*wedpr_vcl_prove_product_balance([c1Result.secret UTF8String], [c2Result.secret UTF8String], [c3Result.secret UTF8String]));

    // Verifies whether three confidential credit records(c1Result, c2Result, c3Result)
    // satisfying a product relationship, i.e. the values embedded in them
    // satisfying c1Value * c2Value = c3Value.
    result = wedpr_vcl_verify_product_balance([c1Result.credit UTF8String], [c2Result.credit UTF8String], [c3Result.credit UTF8String], [productProofStr UTF8String]);

    // Proves whether the value(c1Value) embedded in a confidential credit record(c1Result)
    // belongs to (0, 2^RANGE_SIZE_IN_BITS - 1].
    // RANGE_SIZE_IN_BITS is defined in the dynamic library of VCL, whose typical value is 32.
    NSString *rangeProofStr = @(*wedpr_vcl_prove_range([c1Result.secret UTF8String]));

    // Verifies whether the value(c1Value) embedded in a confidential credit record(c1Result)
    // belongs to (0, 2^RANGE_SIZE_IN_BITS - 1].
    // RANGE_SIZE_IN_BITS is defined in the dynamic library of VCL, whose typical value is 32.
    result = wedpr_vcl_verify_range([c1Result.credit UTF8String], [rangeProofStr UTF8String]);
}

void cryptoDemo() {
    printf("\n*******\nCRYPTO TOOL RUN\n*******\n");
    NSError *error;
    // Generates a keyPair from the secp256k1 curve.
    NSString *keyPairStr = @(*wedpr_secp256k1_gen_key_pair());
    if(keyPairStr.length == 0) {
        // The above API call should not fail.
        printf("API loading error");
        return;
    }
    NSData *decodedData = [[NSData alloc] initWithBase64EncodedString:keyPairStr options:0];
    Keypair *keyPair = [Keypair parseFromData:decodedData error:&error];
    printf("public key = :%s", keyPair.publicKey);
    printf("private key = :%s", keyPair.privateKey);

    // Base64 encoding for "WeDPR Demo", which is currently required to pass bytes input to API.
    // TODO: Allow non-encoded UTF8 input.
    NSString *message = @"V2VEUFIgRGVtbw==";

    // Hashes a message with keccak256 hash.
    NSString *messageHash = @(*wedpr_keccak256_hash([message UTF8String]));
    printf("messageHash = :%s", messageHash);

    // Signs this message hash with ECDSA on the secp256k1 curve.
    NSString *signature = @(*wedpr_secp256k1_sign([keyPair.privateKey UTF8String], [messageHash UTF8String]));
    printf("signature = :%s", signature);

    // Verifies this signature for the above message hash.
    int result = wedpr_secp256k1_verify([keyPair.publicKey UTF8String], [messageHash UTF8String], [signature UTF8String]);
    printf("signature verify result = :%s", result);

    // Encrypts the message with ECIES on the secp256k1 curve.
    NSString *encryptedData = @(*wedpr_secp256k1_ecies_encrypt([keyPair.publicKey UTF8String], [message UTF8String]));
    printf("encryptedData = :%s", encryptedData);

    // Decrypts the message with ECIES on the secp256k1 curve.
    NSString *decryptedData = @(*wedpr_secp256k1_ecies_decrypt([keyPair.privateKey UTF8String], [encryptedData UTF8String]));
    printf("decryptedData = :%s", decryptedData);
}

@end
