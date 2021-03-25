// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

#import "ViewController.h"
#import "Wedpr/WedprCommon.h"
#import "Wedpr/WedprCrypto.h"
#import "Wedpr/WedprVcl.h"
#import "Wedpr/WedprScd.h"
#import "Wedpr/WedprKtb.h"
// TODO: try to move this to protos folder
#import "Common.pbobjc.h"
#import "Vcl.pbobjc.h"
#import "Scd.pbobjc.h"
#import "Hdk.pbobjc.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Test your demo code here.
    cryptoDemo();
    vclDemo(2,2,4);
    scdDemo();

}

void cryptoDemo() {
    printf("\n*******\nCRYPTO DEMO RUN\n*******\n");
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

void vclDemo(unsigned long(c1Value), unsigned long(c2Value), unsigned long(c3Value)) {
    printf("\n*******\nVCL DEMO RUN\n*******\n");
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

void scdDemo() {
    printf("\n*******\nSCD DEMO RUN\n*******\n");
    NSError *error;

    // An issuer defines the certificate schema and generates the certificate template.
    CertificateSchema *schema = [[CertificateSchema alloc] init];
    [schema.attributeNameArray addObject:@"name"];
    [schema.attributeNameArray addObject:@"age"];
    [schema.attributeNameArray addObject:@"gender"];
    [schema.attributeNameArray addObject:@"issue_time"];
    NSString *schemaStr = [[schema data] base64EncodedStringWithOptions:0];

    NSString *scdResultStr = @(*wedpr_scd_make_certificate_template([schemaStr UTF8String]));
    if(scdResultStr.length == 0) {
        // The above API call should not fail.
        printf("API loading error");
        return;
    }
    // TODO: Find a better way to do ScdResult decoding.
    NSData *decodedData = [[NSData alloc] initWithBase64EncodedString:scdResultStr options:0];
    ScdResult *scdResult = [ScdResult parseFromData:decodedData error:&error];
    printf("certificateTemplate = :%s", scdResult.certificateTemplate);
    printf("templatePrivateKey = :%s", scdResult.templatePrivateKey);
    NSString *templatePrivateKeyStr = [[scdResult.templatePrivateKey data] base64EncodedStringWithOptions:0];
    NSString *certificateTemplateStr = [[scdResult.certificateTemplate data] base64EncodedStringWithOptions:0];

    // A user fills the certificate template and prepares a request for the issuer to sign.
    AttributeDict *certificateData = [[AttributeDict alloc] init];
    StringToStringPair *stringToStringPair = [[StringToStringPair alloc] init];
    // TODO: Add a utility function to convert any string to a decimal string.
    // Before this utility function is implemented, the attribute value can only be a decimal
    // string.
    stringToStringPair.key = @"name";
    stringToStringPair.value = @"123";
    [certificateData.pairArray addObject:stringToStringPair];
    stringToStringPair.key = @"age";
    stringToStringPair.value = @"19";
    [certificateData.pairArray addObject:stringToStringPair];
    stringToStringPair.key = @"gender";
    stringToStringPair.value = @"1";
    [certificateData.pairArray addObject:stringToStringPair];
    stringToStringPair.key = @"issue_time";
    stringToStringPair.value = @"12345";
    [certificateData.pairArray addObject:stringToStringPair];
    NSString *certificateDataStr = [[certificateData data] base64EncodedStringWithOptions:0];

    scdResultStr = @(*wedpr_scd_fill_certificate([certificateDataStr UTF8String], [certificateTemplateStr UTF8String]));
    decodedData = [[NSData alloc] initWithBase64EncodedString:scdResultStr options:0];
    scdResult = [ScdResult parseFromData:decodedData error:&error];
    printf("signCertificateRequest = :%s", scdResult.signCertificateRequest);
    printf("userPrivateKey = :%s", scdResult.userPrivateKey);
    printf("certificateSecretsBlindingFactors = :%s", scdResult.certificateSecretsBlindingFactors);
    printf("userNonce = :%s", scdResult.userNonce);

    NSString *certificateSecretsBlindingFactors = scdResult.certificateSecretsBlindingFactors;
    NSString *userPrivateKey = scdResult.userPrivateKey;
    NSString *userNonce = scdResult.userNonce;

    // The issuer verifies the certificate signing request from the user and signs the certificate.
    NSString *signCertificateRequestStr = [[scdResult.signCertificateRequest data] base64EncodedStringWithOptions:0];

    scdResultStr = @(*wedpr_scd_sign_certificate([certificateTemplateStr UTF8String], [templatePrivateKeyStr UTF8String], [signCertificateRequestStr UTF8String], @"123456", [userNonce UTF8String]));
    decodedData = [[NSData alloc] initWithBase64EncodedString:scdResultStr options:0];
    scdResult = [ScdResult parseFromData:decodedData error:&error];
    printf("certificateSignature = :%s", scdResult.certificateSignature);
    printf("issuerNonce = :%s", scdResult.issuerNonce);
    NSString *issuerNonce = scdResult.issuerNonce;

    // The user blinds the received certificateSignature to prevent the issuer to track the
    // certificate usage.
    NSString *certificateSignatureStr = [[scdResult.certificateSignature data] base64EncodedStringWithOptions:0];

    scdResultStr = @(*wedpr_scd_blind_certificate_signature([certificateSignatureStr UTF8String], [certificateDataStr UTF8String], [certificateTemplateStr UTF8String], [userPrivateKey UTF8String], [certificateSecretsBlindingFactors UTF8String], [issuerNonce UTF8String]));
    decodedData = [[NSData alloc] initWithBase64EncodedString:scdResultStr options:0];
    scdResult = [ScdResult parseFromData:decodedData error:&error];
    printf("New certificateSignature = :%s", scdResult.certificateSignature);

    NSString *newCertificateSignatureStr = [[scdResult.certificateSignature data] base64EncodedStringWithOptions:0];

    // A verifier sets a verification rule to:
    // Check AGE > 18 and,
    VerificationRuleSet *verificationRuleSet = [[VerificationRuleSet alloc] init];
    Predicate *predicate = [[Predicate alloc] init];
    predicate.attributeName = @"age";
    predicate.predicateType = @"GT";
    predicate.predicateValue = 18;
    [verificationRuleSet.attributePredicateArray addObject:predicate];
    // Reveal the issue_time attribute.
    [verificationRuleSet.revealedAttributeNameArray addObject:@"issue_time"];
    NSString *verificationRuleSetStr = [[verificationRuleSet data] base64EncodedStringWithOptions:0];

    scdResultStr = @(*wedpr_scd_get_verification_nonce());
    decodedData = [[NSData alloc] initWithBase64EncodedString:scdResultStr options:0];
    scdResult = [ScdResult parseFromData:decodedData error:&error];
    NSString *verificationNonce = scdResult.verificationNonce;

    // The user proves the signed certificate data satisfying the verification rules and does not
    // reveal any extra data.
    scdResultStr = @(*wedpr_scd_prove_selective_disclosure([verificationRuleSetStr UTF8String], [newCertificateSignatureStr UTF8String], [certificateDataStr UTF8String], [certificateTemplateStr UTF8String], [userPrivateKey UTF8String], [verificationNonce UTF8String]));
    decodedData = [[NSData alloc] initWithBase64EncodedString:scdResultStr options:0];
    scdResult = [ScdResult parseFromData:decodedData error:&error];
    printf("verifyRequest = :%s", scdResult.verifyRequest);

    NSString *verifyRequestStr = [[scdResult.verifyRequest data] base64EncodedStringWithOptions:0];

    scdResultStr = @(*wedpr_scd_verify_selective_disclosure([verificationRuleSetStr UTF8String], [verifyRequestStr UTF8String]));
    decodedData = [[NSData alloc] initWithBase64EncodedString:scdResultStr options:0];
    scdResult = [ScdResult parseFromData:decodedData error:&error];
    printf("boolResult = :%s", scdResult.boolResult);

    scdResult = @(*wedpr_scd_get_revealed_attributes([verifyRequestStr UTF8String]));
    decodedData = [[NSData alloc] initWithBase64EncodedString:scdResultStr options:0];
    scdResult = [ScdResult parseFromData:decodedData error:&error];
    printf("revealedCertificateData = :%s", scdResult.revealedAttributeDict);
}

void KtbDemo() {
    printf("\n*******\Ktb DEMO RUN\n*******\n");
    NSError *error;
    // Generates a keyPair from the secp256k1 curve.
    unsigned char word_count = 3;
    NSString *hdkResultStr = @(*wedpr_hdk_create_mnemonic_en(word_count));
    if(hdkResultStr.length == 0) {
        // The above API call should not fail.
        printf("API loading error");
        return;
    }
    NSData *decodedData = [[NSData alloc] initWithBase64EncodedString:hdkResultStr options:0];
    HdkResult *hdkResult = [HdkResult parseFromData:decodedData error:&error];
    
    NSString *mnemonic = hdkResult.masterKey;
    printf("mnemonic = :%s", mnemonic);
    
    NSString *password = @"123456";
    
    hdkResultStr = @(*wedpr_hdk_create_master_key_en([password UTF8String], [mnemonic UTF8String]));
    decodedData = [[NSData alloc] initWithBase64EncodedString:hdkResultStr options:0];
    hdkResult = [HdkResult parseFromData:decodedData error:&error];
    
    NSString *masterKeyStr = [hdkResult.masterKey base64EncodedStringWithOptions:0];
    
    int purpose_type = 44;
    int asset_type = 513866;
    int account = 1;
    int change = 0;
    int address_index = 1000;
    
    
    hdkResultStr = @(*wedpr_hdk_derive_extended_key([masterKeyStr UTF8String], purpose_type, asset_type, account, change, address_index));
    
    NSString *extendedPrivateKey = [hdkResult.keyPair.extendedPrivateKey base64EncodedStringWithOptions:0];
    NSString *extendedPublicKey = [hdkResult.keyPair.extendedPublicKey base64EncodedStringWithOptions:0];
    
    
}

@end
