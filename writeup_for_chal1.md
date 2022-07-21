
# Chal1

### Writeup

This challenge is written in C++. The following is main function we get, when we open in IDA
```
  MD5_Init(v35);
  SHA1_Init(v36);
  for ( i = 0LL; i <= 6; ++i )
  {
    sub_40146D(v32, i);
    v5 = (_QWORD *)std::getline<char,std::char_traits<char>,std::allocator<char>>(&std::cin, v25);
    if ( !std::ios::operator void *((char *)v5 + *(_QWORD *)(*v5 - 24LL)) )
    {
      std::operator<<<std::char_traits<char>>(&std::cout, "The flag is ....", v6);
      sleep(0x283Au);
      v3 = -2;
      goto LABEL_24;
    }
    std::allocator<char>::allocator(v34);
    v7 = std::string::end((std::string *)v25);
    v8 = std::string::begin((std::string *)v25);
    sub_401F7C(v33, v8, v7, v34);
    std::allocator<char>::~allocator(v34);
    sub_401B36(v26, v33);
    sub_40204C(v34, v32);
    LOBYTE(v7) = sub_401B50(v26, v34, &v27);
    sub_401F16(v34);
    if ( (_BYTE)v7 )
    {
      v10 = sub_4014D9(i);
      v11 = qword_6052A0[i + v10];
      if ( v11 == v27 )
      {
        v12 = std::string::size((std::string *)v25);
        v13 = std::string::c_str((std::string *)v25);
        MD5_Update(v35, v13, v12);
        v14 = std::string::size((std::string *)v25);
        v15 = std::string::c_str((std::string *)v25);
        SHA1_Update(v36, v15, v14);
        v18 = 1;
      }
      else
      {
        v16 = std::operator<<<std::char_traits<char>>(&std::cout, "Not good enough.", v11);
        std::ostream::operator<<(v16, &std::endl<char,std::char_traits<char>>);
        v3 = -3;
        v18 = 0;
      }
    }
    else
    {
      v17 = std::operator<<<std::char_traits<char>>(&std::cout, "This is supposed to be easy.", v9);
      std::ostream::operator<<(v17, &std::endl<char,std::char_traits<char>>);
      v3 = -1;
      v18 = 0;
    }
    sub_401FE6(v33);
    if ( v18 != 1 )
      goto LABEL_24;
  }
  MD5_Final(v37, v35);
  SHA1_Final(v38, v36);
  for ( j = 0LL; j <= 0xF; ++j )
    sprintf((char *)&s1[j], "%02x", (unsigned __int8)v37[j]);
  for ( k = 0LL; k <= 0x13; ++k )
    sprintf((char *)&s1[k + 24], "%02x", (unsigned __int8)v38[k]);
  if ( !strcmp((const char *)s1, "3d5f443a57358deb84191dec1bfc65fe") )
  {
    v20 = std::operator<<<std::char_traits<char>>(&std::cout, "That was easy anyways.", v19);
    std::ostream::operator<<(v20, &std::endl<char,std::char_traits<char>>);
    std::operator<<<std::char_traits<char>>(&std::cout, "Here is your flag: flag{", v21);
    for ( l = 0LL; l <= 0x27; ++l )
      std::operator<<<std::char_traits<char>>(
        &std::cout,
        (unsigned int)(char)(*((_BYTE *)&s1[24] + l) ^ qword_605340[l]));
    v23 = std::operator<<<std::char_traits<char>>(&std::cout, "}", v22);
    std::ostream::operator<<(v23, &std::endl<char,std::char_traits<char>>);
  }
  v3 = 0;
LABEL_24:
  std::string::~string((std::string *)v25);
  sub_401F16(v32);
  return v3;
}
```

By going through this code, we can understand that we need to give 7 inputs. First our input is sent to the function ``sub_401B50``. Only when return value from this is 1, we can give our next input. Now we need to check when this function returns 1. 

When we look into the function ``sub_401B50``, we can understand that our input is only numbers and the characters: "+","-","*","/". Based on the return value of ``sub_401E18``, we will know how length of string.

If input is number, it will get stored. The return value of ``sub_401E3E`` will help us to know what are integers should be given each time. Based on the characters we give, operations are performed accordingly.

After performing all operations, final input is compared with fixed value. With the help of this fixed value, we will know which operations we need to give. This continues for every input we give. MD5 and SHA gets updated according to each input we give and final output is compared with ``3d5f443a57358deb84191dec1bfc65fe``.

First input: ``7+6-3/2``
Second input: ``1+4+8``
Third input: ``3``
Fourth input: ``9*9``
Fifth input: ``8+4*9``
Sixth input: ``5/6``
Seventh input: ``3*0``


### Flag
flag{c0u8a_3dgety7_33hygt_donfos_9uck3d_up_NN}