use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use dns_parser::Packet;
use rustls::{ClientSessionMemoryCache, Session};
use state::Storage;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::net::TcpStream;
use std::net::UdpSocket;
use std::str;
use std::sync::Arc;
use webpki;
use webpki_roots;

static TLS_CLIENT_CONFIG: Storage<Arc<rustls::ClientConfig>> = Storage::new();

pub struct Request {
    path: String,
    domain: String,
    ip: String,
}

impl Request {
    pub fn new(domain: String, ip: String, path: String) -> Request {
        return Request {
            path: path,
            domain: domain,
            ip: ip,
        };
    }

    pub fn send(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let rc_config = TLS_CLIENT_CONFIG.get_or_set(|| {
            let mut config = rustls::ClientConfig::new();
            config.set_persistence(ClientSessionMemoryCache::new(128));
            config
                .root_store
                .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

            Arc::new(config)
        });

        let doh_domain = webpki::DNSNameRef::try_from_ascii_str(self.domain.as_str()).unwrap();
        let mut client = rustls::ClientSession::new(&rc_config, doh_domain);

        let http_request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\n\r\n",
            self.path, self.domain
        );
        let mut stream = TcpStream::connect((self.ip.as_str(), 443 as u16))?;

        client.write_all(http_request.as_bytes())?;

        let mut repsonse = [0; 1512];

        let mut size = 0;

        loop {
            while client.wants_write() {
                client.write_tls(&mut stream)?;
            }
            if client.wants_read() {
                if client.read_tls(&mut stream)? == 0 {
                    return Err(From::from("Connection closed"));
                }

                client.process_new_packets()?;
                size = client.read(&mut repsonse)?;

                if size > 0 {
                    break;
                }
            } else {
                break;
            }
        }

        let ok_header_bytes = "HTTP/1.1 200".as_bytes();
        if &repsonse[..ok_header_bytes.len()] == ok_header_bytes {
            return body_from_http_reponse(&repsonse[..size]);
        } else {
            return Err(From::from(format!(
                "HTTP response not 200 OK! {:?}",
                str::from_utf8(&repsonse[..ok_header_bytes.len()])
            )));
        }
    }
}

pub fn body_from_http_reponse(vec: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // find offst for "\r\n\r\n"
    let mut i = 0;
    while i + 4 < vec.len() {
        if vec[i] == '\r' as u8
            && vec[i + 1] == '\n' as u8
            && vec[i + 2] == '\r' as u8
            && vec[i + 3] == '\n' as u8
        {
            i += 4;
            break;
        }
        i += 1;
    }

    return Ok(vec[i..].to_vec());
}

pub fn dns_response(response_buf: &Vec<u8>, socketx: &UdpSocket, src: std::net::SocketAddr) {
    socketx.send_to(response_buf, src).unwrap();
}

pub fn doh_lookup(server: &str, ip: &str, path: &str, request: &[u8]) -> Vec<u8> {
    let full_path =
        path.to_string() + base64::encode_config(request, base64::URL_SAFE_NO_PAD).as_str();

    let request = Request::new(server.to_string(), ip.to_string(), full_path.to_string());
    let resp = request.send().unwrap();

    return resp;
}

pub fn parse_dns_packet(packet_buf: &Vec<u8>) -> Packet {
    let pkt = Packet::parse(packet_buf).unwrap();
    return pkt;
}

pub fn udp_lookup(server: &str, request: &[u8]) -> Vec<u8> {
    let mut buf2 = [0; 2048];
    let socket2 = match UdpSocket::bind("127.0.0.1:0") {
        Ok(s) => s,
        Err(e) => panic!("couldn't bind socket: {}", e),
    };

    socket2.send_to(request, server).unwrap();

    return match socket2.recv_from(&mut buf2) {
        Ok((size, _src2)) => buf2[0..size].to_vec(),
        Err(_) => Vec::new(), //TODO: send error packet
    };
}

pub fn raw_set_ttl(dns_answer: &Vec<u8>, ttl: u32) -> Vec<u8> {
    let mut my_answer = dns_answer.clone();
    // header
    // 16bit ID
    // QR 1BIT
    // OPCODE four bit
    // AA TC RD RA Z
    // RCODE 4bit

    //read QDCOUNT
    let qdcount = BigEndian::read_u16(&my_answer[4..6]);

    //read ANCOUNT
    let ancount = BigEndian::read_u16(&my_answer[6..8]);

    let mut cur_offset = 12 as usize;

    if ancount != 0 {
        for _ in 0..qdcount {
            //QNAME start with length of segments, ends with 0
            while my_answer[cur_offset] != (0 as u8) {
                let len = (my_answer[cur_offset] as usize) + 1;
                cur_offset += len;
            }

            cur_offset += 1;

            //QTYPE
            cur_offset += 2;

            //QCLASS
            cur_offset += 2;
        }

        for _ in 0..ancount {
            if (my_answer[cur_offset] & 0b11000000) == 0b11000000 {
                //handle pointer
                cur_offset += 1;
            } else {
                //NAME start with length of segments, ends with 0
                while my_answer[cur_offset] != (0 as u8) {
                    let len = (my_answer[cur_offset] as usize) + 1;
                    cur_offset += len;
                }
            }
            cur_offset += 1;

            //TYPE
            //println!("TYPE: {}", BigEndian::read_u16(&my_answer[cur_offset..cur_offset + 2]));
            cur_offset += 2;

            //CLASS
            //println!("CLASS: {}", BigEndian::read_u16(&my_answer[cur_offset..cur_offset + 2]));
            cur_offset += 2;

            //TTL
            //let TTL = BigEndian::read_u32(&my_answer[cur_offset..cur_offset+4]);
            BigEndian::write_u32(&mut my_answer[cur_offset..cur_offset + 4], ttl);
            cur_offset += 4;

            //RDLENGTH
            let rdlength = BigEndian::read_u16(&my_answer[cur_offset..cur_offset + 2]) as usize;
            cur_offset += 2;

            //RDATA
            cur_offset += rdlength;
        }
    }

    return my_answer;
}

pub fn get_header_id(dns_packet: &Vec<u8>) -> u16 {
    return BigEndian::read_u16(&dns_packet[0..2]);
}

pub fn fix_up_cache_response(dns_question: &Vec<u8>, mut dns_answer: Vec<u8>) -> Vec<u8> {
    BigEndian::write_u16(&mut dns_answer[0..2], get_header_id(dns_question));
    dns_answer = raw_set_ttl(&dns_answer, 12345);

    return dns_answer;
}

pub fn local_answer(pkt: &Packet, ip: IpAddr, name: &String, ttl: i32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);

    let m = format!("{}", name);
    let name = m.as_str();

    let head = dns_parser::Header {
        id: pkt.header.id,
        query: false,
        opcode: dns_parser::Opcode::StandardQuery,
        authoritative: true,
        truncated: false,
        recursion_desired: true,
        recursion_available: true,
        authenticated_data: false,
        checking_disabled: false,
        response_code: dns_parser::ResponseCode::NoError,
        questions: 1,
        answers: 1,
        nameservers: 0,
        additional: 0,
    };
    buf.extend([0u8; 12].iter());

    head.write(&mut buf[..12]);

    for part in name.split('.') {
        assert!(part.len() < 63);
        let ln = part.len() as u8;
        buf.push(ln);
        buf.extend(part.as_bytes());
    }

    buf.push(0);
    match ip.clone() {
        IpAddr::V4(_) => {
            buf.write_u16::<BigEndian>(1).unwrap();
        }
        IpAddr::V6(_) => {
            buf.write_u16::<BigEndian>(28).unwrap();
        }
    }

    buf.write_u16::<BigEndian>(1).unwrap();

    for part in name.split('.') {
        assert!(part.len() < 63);
        let ln = part.len() as u8;
        buf.push(ln);
        buf.extend(part.as_bytes());
    }
    buf.push(0);

    match ip {
        IpAddr::V4(ipv4) => {
            //TYPE A 1
            buf.write_u16::<BigEndian>(1 as u16).unwrap();

            //CLASS IN 1
            buf.write_u16::<BigEndian>(1).unwrap();

            //TTL 32 bit signed integer
            buf.write_i32::<BigEndian>(ttl).unwrap();

            //RDLENGTH  unsigned 16 bit integer
            buf.write_u16::<BigEndian>(4 as u16).unwrap();

            buf.write_u32::<BigEndian>(u32::from(ipv4)).unwrap();
        }
        IpAddr::V6(ipv6) => {
            //TYPE AAAA 28
            buf.write_u16::<BigEndian>(28 as u16).unwrap();

            //CLASS IN 1
            buf.write_u16::<BigEndian>(1).unwrap();

            //TTL 32 bit signed integer
            buf.write_i32::<BigEndian>(ttl).unwrap();

            //RDLENGTH  unsigned 16 bit integer
            buf.write_u16::<BigEndian>(16 as u16).unwrap();
            for segment in ipv6.segments().iter() {
                buf.write_u16::<BigEndian>(*segment).unwrap();
            }
        }
    }

    buf.push(0);
    return buf.to_vec();
}

pub fn name_error_answer(pkt: &Packet, ip: IpAddr, name: &String) -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);

    let m = format!("{}", name);
    let name = m.as_str();

    let head = dns_parser::Header {
        id: pkt.header.id,
        query: false,
        opcode: dns_parser::Opcode::StandardQuery,
        authoritative: true,
        truncated: false,
        recursion_desired: true,
        recursion_available: true,
        authenticated_data: false,
        checking_disabled: false,
        //signifies that the domain name referenced in the query does not exist
        response_code: dns_parser::ResponseCode::NameError,
        questions: 1,
        answers: 0,
        nameservers: 0,
        additional: 0,
    };
    buf.extend([0u8; 12].iter());

    head.write(&mut buf[..12]);

    for part in name.split('.') {
        assert!(part.len() < 63);
        let ln = part.len() as u8;
        buf.push(ln);
        buf.extend(part.as_bytes());
    }

    buf.push(0);
    match ip {
        IpAddr::V4(_) => {
            buf.write_u16::<BigEndian>(1).unwrap();
        }
        IpAddr::V6(_) => {
            buf.write_u16::<BigEndian>(28).unwrap();
        }
    }

    buf.write_u16::<BigEndian>(1).unwrap();

    for part in name.split('.') {
        assert!(part.len() < 63);
        let ln = part.len() as u8;
        buf.push(ln);
        buf.extend(part.as_bytes());
    }

    return buf.to_vec();
}

pub fn refuse_query_truncated_answer(pkt: &Packet) -> Vec<u8> {
    let mut buf = Vec::with_capacity(13);

    //force tcp connection with truncated: true works for nslookup
    let head = dns_parser::Header {
        id: pkt.header.id,
        query: false,
        opcode: dns_parser::Opcode::ServerStatusRequest,
        authoritative: false,
        truncated: true,
        recursion_desired: false,
        recursion_available: false,
        authenticated_data: false,
        checking_disabled: false,
        response_code: dns_parser::ResponseCode::Refused,
        questions: 0,
        answers: 0,
        nameservers: 0,
        additional: 0,
    };
    buf.extend([0u8; 12].iter());

    head.write(&mut buf[..12]);

    return buf;
}
