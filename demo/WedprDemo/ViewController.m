// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

#import "ViewController.h"
#import "Wedpr/WedprCommon.h"
#import "Wedpr/WedprCrypto.h"
#import "Wedpr/WedprVcl.h"
#import "Wedpr/WedprSelectiveDisclosure.h"
// TODO: try to move this to protos folder
#import "Common.pbobjc.h"
#import "Vcl.pbobjc.h"
#import "SelectiveDisclosure.pbobjc.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Test your demo code here.
    vclDemo(2,2,4);
    cryptoDemo();
    selectiveDisclosureDemo();

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

void selectiveDisclosureDemo() {
    printf("\n*******\nSELECTIVE DISCLOSURE RUN\n*******\n");
    // issuer make template

    NSError *error;
    AttributeTemplate *attributeTemplate = [[AttributeTemplate alloc] init];
    [attributeTemplate.attributeKeyArray addObject:@"age"];
    [attributeTemplate.attributeKeyArray addObject:@"id"];
    [attributeTemplate.attributeKeyArray addObject:@"time"];
    
    
    NSString *attributeTemplateStr = [[attributeTemplate data] base64EncodedStringWithOptions:0];
    
    NSString *selectiveDisclosureResultStr = @(*wedpr_make_credential_template([attributeTemplateStr UTF8String]));
    if(selectiveDisclosureResultStr.length == 0) {
        // The above API call should not fail.
        printf("API loading error");
        return;
    }
    NSData *decodedData = [[NSData alloc] initWithBase64EncodedString:selectiveDisclosureResultStr options:0];
    SelectiveDisclosureResult *selectiveDisclosureResult = [Keypair parseFromData:decodedData error:&error];
    printf("credentialTemplate = :%s", selectiveDisclosureResult.credentialTemplate);
    printf("templateSecretKey = :%s", selectiveDisclosureResult.templateSecretKey);
    NSString *templateSecretKeyStr = [[selectiveDisclosureResult.templateSecretKey data] base64EncodedStringWithOptions:0];
    
    // User fill template
    CredentialInfo *credentialInfo = [[CredentialInfo alloc] init];
    StringToStringPair *stringToStringPair = [[StringToStringPair alloc] init];
    stringToStringPair.key = @"age";
    stringToStringPair.key = @"18";
    [credentialInfo.attributePairArray addObject:stringToStringPair];
    stringToStringPair.key = @"id";
    stringToStringPair.key = @"123456";
    [credentialInfo.attributePairArray addObject:stringToStringPair];
    stringToStringPair.key = @"time";
    stringToStringPair.key = @"20201124";
    [credentialInfo.attributePairArray addObject:stringToStringPair];
    
    NSString *credentialInfoStr = [[credentialInfo data] base64EncodedStringWithOptions:0];
    
    NSString *credentialTemplateStr = [[selectiveDisclosureResult.credentialTemplate data] base64EncodedStringWithOptions:0];

    selectiveDisclosureResultStr = @(*wedpr_make_credential([credentialInfoStr UTF8String], [credentialTemplateStr UTF8String]));
    printf("credentialSignatureRequest = :%s", selectiveDisclosureResult.credentialSignatureRequest);
    printf("masterSecret = :%s", selectiveDisclosureResult.masterSecret);
    printf("credentialSecretsBlindingFactors = :%s", selectiveDisclosureResult.credentialSecretsBlindingFactors);
    printf("userNonce = :%s", selectiveDisclosureResult.nonce);
    
    NSString *credentialSecretsBlindingFactors = selectiveDisclosureResult.credentialSecretsBlindingFactors;
    NSString *masterSecret = selectiveDisclosureResult.masterSecret;
    

    
    // Issuer sign user's request to generate credential
    NSString *credentialSignatureRequestStr = [[selectiveDisclosureResult.credentialSignatureRequest data] base64EncodedStringWithOptions:0];
    NSString *masterSecretStr = selectiveDisclosureResult.masterSecret;
    
    selectiveDisclosureResultStr = @(*wedpr_sign_credential([credentialTemplateStr UTF8String], [templateSecretKeyStr UTF8String], [credentialSignatureRequestStr UTF8String], @"id1", [selectiveDisclosureResult.nonce UTF8String]));
    
    printf("credentialSignature = :%s", selectiveDisclosureResult.credentialSignature);
    printf("nonceCredential = :%s", selectiveDisclosureResult.nonceCredential);
    NSString *nonceCredential = selectiveDisclosureResult.nonceCredential;
    
    // User generate new credentialSignature
    NSString *credentialSignatureStr = [[selectiveDisclosureResult.credentialSignature data] base64EncodedStringWithOptions:0];
    
    selectiveDisclosureResultStr = @(*wedpr_blind_credential_signature([credentialSignatureStr UTF8String], [credentialInfoStr UTF8String], [credentialTemplateStr UTF8String], [masterSecret UTF8String], [credentialSecretsBlindingFactors UTF8String], [nonceCredential UTF8String]));
    
    printf("New credentialSignature = :%s", selectiveDisclosureResult.nonceCredential);
    NSString *newCredentialSignatureStr = [[selectiveDisclosureResult.credentialSignature data] base64EncodedStringWithOptions:0];
    

    // Verifier set verification rules
    VerificationRule *verificationRule = [[VerificationRule alloc] init];
    Predicate *predicate = [[Predicate alloc] init];
    predicate.attributeName = @"age";
    predicate.predicateType = @"GT";
    predicate.value = 17;
    [verificationRule.predicateAttributeArray addObject:predicate];
    predicate.attributeName = @"gender";
    predicate.predicateType = @"EQ";
    predicate.value = 1;
    [verificationRule.predicateAttributeArray addObject:predicate];
    
    NSString *verificationRuleStr = [[verificationRule data] base64EncodedStringWithOptions:0];
    
    selectiveDisclosureResult = @(*wedpr_prove_credential_info([verificationRuleStr UTF8String], [newCredentialSignatureStr UTF8String], [credentialInfoStr UTF8String], [credentialTemplateStr UTF8String], [masterSecret UTF8String]));
    
    printf("verificationRequest = :%s", selectiveDisclosureResult.verificationRequest);
    
    NSString *verificationRequestStr = [[selectiveDisclosureResult.verificationRequest data] base64EncodedStringWithOptions:0];
    
    selectiveDisclosureResult = @(*wedpr_verify_proof([verificationRuleStr UTF8String], [verificationRequestStr UTF8String]));
    printf("result = :%s", selectiveDisclosureResult.result);
    
    selectiveDisclosureResult = @(*wedpr_get_revealed_attrs_from_verification_request([verificationRequestStr UTF8String]));
    printf("revealedAttributeInfo = :%s", selectiveDisclosureResult.revealedAttributeInfo);
}
@end
