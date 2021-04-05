package main;

import java.util.ArrayList;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;



public class Main {


  public static void main(String[] args) {
    // 네트워크 어댑터들을 저장할 수 있는 배열생성
    ArrayList<PcapIf> allDevs = new ArrayList<PcapIf>();
    // 오류 메시지를 담을 수 있는 변수 생성
    StringBuilder errbuf = new StringBuilder();
    // 오류 발생시 errbuf안에 오류들을 담게 된다.
    int r = Pcap.findAllDevs(allDevs, errbuf);
    // Pcap이 -1이거나 비어있으면 오류 발생 메시지 출력
    if (r == Pcap.NOT_OK || allDevs.isEmpty()) {
      System.out.println("네트워크 장치를 찾을 수 없습니다." + errbuf.toString());
      return;
    }
    System.out.println("네트워크 장비 탐색 성공!!");
    int i = 0;
    // 장치에 존재하는 네트워크들을 모두 탐색하여 null이 아니면 현재장치 설명담는 변수
    for (PcapIf device : allDevs) {
      String description = (device.getDescription() != null) ? device.getDescription() : "장비에 대한 설명이 없습니다.";
      System.out.printf("[%d]번 : %s [%s]n\n", i++, device.getName(), description);
    }

    // 실제 사용할 네트워크를 지정하기 (나 같은 경우는 [Intel(R) I211 Gigabit Network Connection]
    PcapIf device = allDevs.get(1);
    System.out.printf("선택한 장치 : %s\n", (device.getDescription() != null) ? device.getDescription() : device.getName());

    int snaplen = 64 * 1024; // 패킷을 얼마나 캡쳐할 것인지에 대한 옵션
    int flags = Pcap.MODE_NON_PROMISCUOUS; // 패킷검열 없이 받아들이는 옵션
    int timeout = 10 * 1000; // 10000ms 만큼 timeout 설정
    Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
    // 에러 발생시 에러메시지 출력
    if (pcap == null) {
      System.out.printf("패킷 캡처를 위해 네트워크 장치를 여는 데 실패했습니다. 오류 : " + errbuf.toString());
      return;
    }
    // 네트워크 2계층 정보를 담는다
    Ethernet eth = new Ethernet();
    // 네트워크 3계층 정보를 담는다
    Ip4 ip = new Ip4();
    // 네트워크 4계층 정보를 담는다
    Tcp tcp = new Tcp();
    // 서버와 통신해서 데이터를 주고 받을 때 데이터가 들어가는 공간(ex. 로그인)
    Payload payload = new Payload();
    // 패킷 헤더
    PcapHeader header = new PcapHeader(JMemory.POINTER);
    // 패킷 버퍼
    JBuffer buf = new JBuffer(JMemory.POINTER);
    // 패킷 캡처시 필요한 id값
    int id = JRegistry.mapDLTToId(pcap.datalink());

    // 오류가 발생하지 않는 한 계속해서 패킷을 캡처할 수 있도록 하는 While 구문
    while (pcap.nextEx(header, buf) != Pcap.NEXT_EX_NOT_OK) {
      PcapPacket packet = new PcapPacket(header, buf);
      packet.scan(id);
      System.out.printf("[ #%d ]\n", packet.getFrameNumber());
      if (packet.hasHeader(eth)) {
        System.out.printf("출발지 MAC 주소 = %s\n도착지 MAC 주소 = %s\n", FormatUtils.mac(eth.source()),
        		FormatUtils.mac(eth.destination()));
      }
      if (packet.hasHeader(ip)) {
        System.out.printf("출발지 IP 주소 = %s\n도착지 IP 주소 = %s\n",
        		FormatUtils.ip(ip.source()), FormatUtils.ip(ip.destination()));
      }
      if (packet.hasHeader(tcp)) {
        System.out.printf("출발지 TCP 주소 = %d\n도착지 TCP 주소 = %d\n",
        		tcp.source(), tcp.destination());
      }
      if(packet.hasHeader(payload)) {
        System.out.printf("페이로드의 길이 = %d\n", payload.getLength());
        System.out.print(payload.toHexdump());
      }
    }
    pcap.close();
  }
}
