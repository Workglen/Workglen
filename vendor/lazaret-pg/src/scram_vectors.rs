// PostgreSQL 16 verifier fixtures from the pinned Lazaret test suite.
#[test] fn postgres16_password_verifiers(){
let vectors:&[(&[u8],&str)]=&[
(b"\x61\xc2\xad\x62\xc3\xa9","4096:/mdlgrtarJPSnjNEHnOTFg==$mvngpSPrhY/e97CRJhZ/pWxvrs26/2B66NlP7kO6ol4="),
(b"\xc2\xad\xc2\xad","4096:HivWLoFDENJzmfo9rgtCow==$r0u3lC2AGBr1o9IGVm1KVFsyI/TdniY/aNNOez8gMqA="),
(b"\xc3\xa9\x09\x7a","4096:Ub1E/BFVfEcFpjLS35oWmA==$t+T57NvtHHb2e70TjTr+pKYNs48X9DlTs22jOG7YxWs="),
(b"\xd8\xa7\x31\xd8\xa8","4096:Tf4h2yeJnl7Sd9FC7L/biQ==$LyTelqYeH0fKO7HPi6jdf272vVW06hfYb83+RWWkCt0="),
(b"\xd8\xa7\x61","4096:3ARLLKbVMDkgbOacK1gN7g==$5OyhZ8q4M8vpwnJi07QGD8Y8ujaSJZhunlJeXFKm+9I="),
(b"\xef\xac\x81\x78","4096:pHN1KLMMGNODfXzZZ/jM+g==$1HMHiGlmEWVnCwyOgAxf45Rxa9g7/YecN1FUuJFAWpM="),
(b"\x61\xc2\xa0\x62\xc3\xa9","4096:at9w5twGrEHzw2DwHJKT3g==$gfJJu12kLdOeaWEZN8pYG3u/+TmehwDHQOaQsu8G3As="),
(b"\xc3\xa9\x7f","4096:2kOiitgLJ2dSJuruKSg10A==$GtnWtrwrYQRzDFsHK2/ot5mSfEvVucoeC01wphB9kag="),
(b"\xf0\x9f\x84\x80\x78","4096:HzeCRvmS2/jezCUsYbrjJQ==$QJBrf91O7RFSZc2Lsl56P5Z7HtUyHH/EBhXE5yjxwbM="),
(b"\x65\xcd\x81\x78","4096:BCG0zr+CIbCd8kuK9rj0WQ==$TNWyCDxqLkdW2cqPZdSDp8lFIIB/HEBHzVhmzdyyevQ="),
(b"\xef\xa9\xb0\x78","4096:SdWF3X2PP/EICfuOsFsL9g==$0ESx9OrTA1A21CCYCD2FqKqqaZQeDaCM6IFQdwh3Tq0="),
(b"\xe2\x85\x90\x78","4096:lraE57+vlWa2G2e8z290nQ==$1I0hp4VGapaLhM8Vl53+svpO+pQhJ7iF7IjgwbCM7Us="),
(b"\xf0\x9f\x84\xb0\x62\x63","4096:ihbG16+nSvCcXGplN6/dvA==$zBYB/ihDEqX/rmBnVkIhQjYgHhEVIF3FNP8NEOy43io="),
(b"\xe2\x84\x8c\xf0\x9f\x99\x82","4096:A395lVCKK7SfkzraRlY9sA==$9iiLylEdzm7xR5y4rNEtISirvKngkiAdHRS0Y7WvJ48="),
(b"\x70\xc3\xa4\x73\x73\x77\xc3\xb6\x72\x64\x20\xe2\x84\x8c","4096:Dqp1/RqdYXO44a7W0MpNxQ==$dpHfVPbREXYQZ6QmiG6Fez8Y81q89EvGiYIer/0lml8="),
(b"\xf0\xaf\xa1\xa8\x78","4096:ZiSCD51Eeh2VssA3tQiVTg==$SH5XsLu0Py/x0qRMvdRAGvNkhgg62OBvt3uTA3nPWtg="),
(b"\xf0\xaf\xa1\xb4\x78","4096:Flan1uuWb8F3G7ytdkbxxg==$RfqYKmWlPjRvsHi8VEsq87OqD4WawvtkKsxXsAWLFCc="),
(b"\xf0\xaf\xa4\x9f\x78","4096:L2mkKAosDWnd3SkeXV7a7w==$ah5mo3Z0geWoWdeCdb6Rcspp5LgpJOAQc0gNHkJaxP4="),
(b"\xf0\xaf\xa5\x9f\x78","4096:PBYdCLMmxUvpjRWK1BzWiA==$aIzLNye1XeFbwDJpdK/VgEoh7i+neaV6voiwDva50xA="),
(b"\xf0\xaf\xa6\xbf\x78","4096:LI1rht0i7l5w4AIC/V4YLg==$o5eE1KwPYWDhes5flH3TfoetYwFuOgF2QKhhQ/Cs6xw="),
];
for (password,verifier) in vectors {let c=Scram::with_nonce(password,None,false,"nonce","").unwrap();let (head,stored)=verifier.split_once('$').unwrap();let (count,salt)=head.split_once(':').unwrap();let salted=salted(&c.password,&decode(salt).unwrap(),count.parse().unwrap()).unwrap();let key=hmac(&salted,b"Client Key");assert_eq!(base64_encode(&Sha256::digest(&key)),stored);}
}
