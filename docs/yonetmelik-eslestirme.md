# SpaceGoat ve Siber Güvenlik Başkanlığı yönetmelik taslakları

Bu belge, iki yönetmelik taslağının hangi maddesinin SpaceGoat'ı ilgilendirdiğini, SpaceGoat'ın o konuda bugün ne yaptığını ve ne yapmadığını söyler.

## 1. Bu belge nedir, ne değildir

- Kaynak iki **taslak** metindir. Madde numaraları ve ifadeler nihai metinde değişebilir.
- Bu belge hukuki görüş değildir ve bir kuruluşun yükümlülüklerini yerine getirdiğini göstermez. Bunu ancak kuruluşun kendisi ve denetçisi değerlendirir.
- "SpaceGoat ne yapar" sütunu yazılımın bir özelliğini anlatır, bir yükümlülüğün karşılandığını değil.
- Kendi çıkarımlarımız kaynaktan ayrı tutulmuştur ve "Yorum:" ile başlar.

Okunan metinler (27.11.2026 tarihinde indirilen sürümler):

| Kısaltma | Metin | Kaynak | SHA-256 |
|---|---|---|---|
| D | Siber Dayanıklılık Yönetmeliği Taslağı (76 madde, 2 geçici madde) | [siberguvenlik.gov.tr](https://cdn.siberguvenlik.gov.tr/public/news/siber-dayaniklilik-yonetmeligi.pdf) | `40d74e18de0f9e7b5bb4888f0521619a70f5a734671ccc7cfe4afc20a7eae750` |
| N | Denetim Yönetmeliği Taslağı (36 madde, 1 geçici madde) | [siberguvenlik.gov.tr](https://cdn.siberguvenlik.gov.tr/public/news/denetim_yonetmeligi_taslagi.pdf) | `07a0e21c1dada4896f9166b77070835e913cad326d19cac673432b32f687e6a2` |

Alıntılar PDF'lerden çıkarılan metinden birebir alınmıştır.

SpaceGoat'ın bugünkü durumu:

- [Protokol v1](../spec/protocol.md) ve test vektörleri yayımdadır.
- [Kayıt dökümü biçimi v1](../spec/export.md) ve ondan bağımsız yazılmış bir [doğrulayıcı](../spec/verify/README.md) depodadır. Döküm üreten bölüm bu depoda yoktur.
- Hub ajanı geliştirme aşamasındadır; yayımlanmış bir sürümü yoktur.
- Ağı dinleyen bölümler henüz yazılmamıştır. Aşağıda envanterle ilgili satırların durumu bu yüzden `planlı`dır.

## 2. Taslaklar kime uygulanır

| Bölüm (D) | Maddeler | Kimi bağlar | Yürürlük (D md. 75) |
|---|---|---|---|
| Dördüncü bölüm, genel yükümlülükler | 26-27 | herkes | yayım tarihi |
| Beşinci bölüm | 28-50 | kurumsal SOME kurma yükümlülüğü getirilenler ve kamu kurumları (md. 71/1) | yayımdan altı ay sonra |
| Altıncı bölüm | 51-70 | kritik altyapıya sahip kuruluşlar | yayımdan bir yıl sonra |

Denetim taslağı (N) 7545 sayılı Kanun kapsamındaki bütün tarafları kapsar; birçok hükmü, Başkanlığın yayımlayacağı uygulama esaslarıyla birlikte uygulanır (N md. 35, geçici md. 1).

## 3. Eşleştirme

Durum sözlüğü:

- `var`: yazılımın bu özelliği bugün depodadır.
- `kısmen`: bir bölümü depodadır; eksik olan satırda yazılıdır.
- `planlı`: henüz yazılmamıştır, yapılması planlanmıştır.
- `yok`: SpaceGoat bunu yapmaz.

<!-- eslestirme:basla -->
| Konu | Madde (taslak) | Taslak metni | SpaceGoat ne yapar | Kanıtı | Durum |
|---|---|---|---|---|---|
| Merkezi varlık envanteri | D md. 30(1) | "BGYS kapsamındaki tüm bilişim sistemi ve varlıkların, aralarındaki karşılıklı bağımlılıklarını, yaşam döngüsü durumlarını ve üstlendikleri kritik iş fonksiyonlarını gösterecek şekilde dokümante edilerek merkezi bir varlık envanteri oluşturulur." | Ağda görülen cihazlar için ilk görülme, değişiklik, son görülme ve dönemsel sayım olayları üretir. Olay türleri protokolde tanımlıdır; ağ dinleyicileri yazılmamıştır. Envanterin kendisini kuruluş tutar. | [protokol, bölüm 9](../spec/protocol.md) | planlı |
| Envanterde ağ bölgesi | D md. 30(2) | "Varlığın fiziksel, mantıksal, sanal, bulut veya coğrafi konumu, ağ bölgesi, dışa açıklığı bilgisi." | Cihazın hangi ağ bölümünde görüldüğünü ve tahmini sınıfını bildirir. Sahip, amaç, sürüm, seri numarası, lisans ve destek bilgisi vermez. | [protokol, bölüm 9](../spec/protocol.md) | planlı |
| Değişikliğin envantere yansıması | D md. 30(5) | "Varlıklarda meydana gelen her türlü değişiklik, ekleme veya devreden çıkarma işleminde envanter eş zamanlı olarak güncellenir." | Yeni görülen, değişen ve artık görülmeyen cihazı gözlendiği anda kayda geçirir. Envanteri güncellemek kuruluşun işidir. | [protokol, bölüm 9](../spec/protocol.md) | planlı |
| Envanterin gözden geçirilmesi | D md. 30(8) | "Varlık envanteri en az yılda bir kez; önemli bir siber olay, mimari değişiklik, yeni kritik hizmet, tedarikçi değişikliği, birleşme veya kuruluş yapısında değişiklik olması durumunda ise yeniden gözden geçirilir." | Gözden geçirmede beyan edilen envanterle karşılaştırılabilecek bir gözlem kaydı sağlar. | [protokol, bölüm 9](../spec/protocol.md) | planlı |
| UVET'e bildirim | D md. 7(3) | "Bu bilgilerde meydana gelen değişiklikler aksi Başkanlıkça belirtilmedikçe en geç bir ay içerisinde aynı yöntemle Başkanlığa bildirilir." | Bildirim yapmaz. UVET'in veri modeli henüz belirlenmemiştir (D md. 7/6). | | yok |
| Tedarikçinin kullandığı varlıklar | D md. 43(4) | "Tedarikçilerin kullandığı kurumsal bilişim varlıkları, hesaplar, sertifikalar, anahtarlar, yapılandırmalar ve veriler envantere kaydedilir." | Ağda görülen her cihazı, kimin olduğu bilinmese de kaydeder. Cihazın bir tedarikçiye ait olduğunu bilemez. | [protokol, bölüm 9](../spec/protocol.md) | planlı |
| Kayıtların eksiksiz ve kronolojik olması | D md. 42(1) | "Bilişim sistemlerinde gerçekleşen kullanıcı, sistem ve erişim hareketlerine ilişkin log kayıtları eksiksiz, tutarlı ve kronolojik olarak oluşturulur." | Yalnız Hub'ın kendi kayıtları için: her olay kesintisiz bir sıra numarası taşır, eksik aralık açıkça beyan edilir. Kuruluşun kullanıcı ve sistem loglarını üretmez. | [protokol, bölüm 8](../spec/protocol.md) | kısmen |
| Kayıtların değiştirilmeye karşı korunması | D md. 42(3) | "Log kayıtları, değiştirilmesini, silinmesini veya yetkisiz erişilmesini engelleyecek şekilde kriptografik yöntemler veya zaman damgası kullanılarak korunur, en az iki yıl süreyle güvenli ortamlarda saklanır ve yedeklenir." | Yalnız Hub'ın kendi kayıtları için: her olay Hub'da Ed25519 ile imzalanır; değişiklik, silme ve araya ekleme sonradan görülebilir. Saklama süresi Hub'ın değil servisin işidir. Protokol yayımdadır, ajan geliştirme aşamasındadır. | [protokol, bölüm 3, 4 ve 8](../spec/protocol.md) | kısmen |
| Olayın zaman çizelgesi | D md. 33(5) | "Saldırının başlangıcından olayın tespit edilmesine kadar geçen süre içerisinde saldırganların davranışlarına ilişkin zaman çizelgesi." | Bir cihazın ağda ilk ve son görüldüğü anı imzalı olarak kaydeder; çizelgeye girdi olabilir. Saldırgan davranışını tespit etmez. | [protokol, bölüm 4 ve 9](../spec/protocol.md) | planlı |
| Olay bildirimi süreleri | D md. 33(1) | "siber olayın tespit edilmesinden itibaren en geç on iki saat içinde mevcut bilgiler ve teknik verilerle birlikte bildirilir." | Bildirim yapmaz; bildirimi kuruluş yapar. | | yok |
| Zaman sapması | D md. 44(2) | "Zaman kaynağına erişilememesi, senkronizasyon hatası veya kabul edilebilir sapmanın aşılması hâlinde olay tespit edilir, sorumlu birime bildirilir, alternatif zaman kaynağı devreye alınır ve kayıtların güvenilirliğini koruyacak tedbirler uygulanır." | Hub saatini servisin saatiyle karşılaştırır; saatine güvenemediği sürece kayıt üretmez. Sapmayı ayrı bir olay olarak bildirmesi planlanmıştır. | [protokol, bölüm 11](../spec/protocol.md) | planlı |
| Ulusal zaman kaynağı | D md. 51(12) | "Kritik altyapıya sahip kuruluşlar 44 üncü maddede belirtilen zaman senkronizasyonunu, atomik saat standardına dayalı güvenli, kesintisiz ve doğrulanabilir ulusal zaman kaynaklarını kullanarak sağlar." | Zaman kaynağı seçmez. Hub'ın üzerinde çalıştığı sistemin saatini kuruluş ayarlar. | | yok |
| Misafir ağının ayrılması | D md. 38(4) | "Kritik bilişim sistemleri, sunucu ortamları ve veri tabanları ile genel kullanıcı ve misafir ağları birbirinden bağımsız ağlara bölünür. Misafir ağı, kurumsal kaynaklara erişim sağlayamaz." | Bir ağ bölümünde beklenmeyen bir cihazın görüldüğünü bildirmesi planlanmıştır. Ayrımın yapıldığını gösteremez. | | planlı |
| Veri toplayan uç cihazların ağa alınması | D md. 61(1) | "bağlantının diğer ağ bölümlerinden fiziksel veya mantıksal olarak ayrılması, kullanılmayan erişim ve yönetim protokollerinin kapatılması, uygun kimlik doğrulama ve yetkilendirme yöntemlerinin uygulanması zorunludur." | Hub'ın kendisi için: yalnız dışa bağlanır, gelen bağlantı ve komut kabul etmez, tek bir servise konuşur ve her isteğini imzalar. Ayrı bir ağ bölümüne konması ise dinlediği ağın içinde olma ihtiyacıyla çelişir (bölüm 5). | [protokol, bölüm 1 ve 5](../spec/protocol.md) | kısmen |
| Uç cihaz verisinin merkezi izlemeye bağlanması | D md. 61(6) | "Bu maddede belirtilen gelişen teknolojilerden üretilen tüm güvenlik ve anomali verileri, 62 nci maddede yer alan teknik mimari ile entegre şekilde işletilir." | Hub verisini yalnız yapılandırıldığı servise gönderir. Kuruluşun kendi izleme sistemine aktarım yoktur. | | yok |
| Açık kaynak bileşenlerin doğrulanması | D md. 56(5) | "Kurumsal sistemlerde veya yazılım geliştirme süreçlerinde açık kaynak kodlu yazılım, kütüphane ve bileşenlerin kullanımı, ancak bunların kaynak güvenilirliği doğrulandıktan ve gerekli güvenlik testlerinden geçirildikten sonra gerçekleştirilir." | Kaynak kodu ve protokol açıktır; doğrulamayı kullanan kuruluş yapar. İmzalı sürüm yayımlanması planlanmıştır. | [güvenlik bildirimi](../SECURITY.md) | planlı |
| Yazılım bileşen listesi | D md. 56(4) | "Kritik sistemlerde yazılım bileşen listesi veya bağımlılık haritası tutulur." | Her sürümle birlikte bileşen listesi yayımlanması planlanmıştır. | | planlı |
| Verinin Türkiye'de barındırılması | D md. 58(2) | "Bu sistemler ve veriler, ülkemizde tesisli ve Başkanlıkça yetkilendirilen hizmet sağlayıcılar bünyesinde barındırılabilir." | Hub yalnız kurulumda yazılan tek adrese konuşur ve yönlendirme izlemez. Servisin nerede barındığı ve yetkilendirilmesi Hub'ın dışındadır. | [protokol, bölüm 5](../spec/protocol.md) | kısmen |
| Kamuya açık yapay zekâ modellerine veri aktarımı | D md. 61(5) | "Kritik altyapıya sahip kuruluşlar; kamuya açık yapay zekâ modellerine veri aktaramaz." | Hub hiçbir üçüncü tarafa veri göndermez. Servisin veriyi nasıl işlediği Hub'ın dışındadır. | [protokol, bölüm 5](../spec/protocol.md) | kısmen |
| Denetim kanıtının bütünlüğü | N md. 18(3) | "Denetim kapsamında elde edilen kanıtların bütünlüğü ve izlenebilirliği korunur." | Hub kayıtlarının imzası ve sıra numarası, kayıt servise ulaştıktan sonra da denetlenebilir. Ajan geliştirme aşamasındadır. | [protokol, bölüm 4](../spec/protocol.md) | kısmen |
| Elektronik doğrulama verisi | N md. 14(7) | "Elektronik ortamda sunulan bilgi, belge ve doğrulama verileri denetim kanıtı olarak kabul edilir ve denetim kanıtı başlıklı madde hükümlerine göre muhafaza edilir." | Döküm biçimi, test vektörleri ve bir dökümü SpaceGoat koduna bağlı kalmadan denetleyen tek dosyalık doğrulayıcı depodadır. Doğrulayıcı imzayı, sıra numarasını ve özet taahhüdünü denetler; anahtarın cihaza ait olduğunu göstermez, okuyan kişi parmak izini kayıt tutanağıyla karşılaştırır. Dökümün saklanması kuruluşun işidir. | [döküm biçimi](../spec/export.md), [doğrulayıcı](../spec/verify/README.md) | var |
| Kanıtta kişisel veri | N md. 18(4) | "Kanıtların elde edilmesi, taşınması, saklanması ve kullanılması sırasında gizlilik ile kişisel verilerin korunmasına ilişkin mevzuat hükümlerine uyulur." | Donanım adresi, cihaz adı ve IP adresi imzalı kayıttan ayrı taşınır; yalnız özet taahhüdü imzalanır. Kişisel veri silindiğinde kaydın imzası geçerli kalır. | [protokol, bölüm 6](../spec/protocol.md) | var |
| Öz değerlendirmenin kanıtla sunulması | N md. 25(3) | "Öz değerlendirme sonuçları, gerekli kanıt ve kayıtlarla birlikte Başkanlığa belirlenen usul ve esaslar çerçevesinde bildirilir veya erişilebilir hale getirilir." | Kayıt dökümünün biçimi ve doğrulayıcısı depodadır. Dökümü üreten bölüm bu depoda yoktur; dökümü kayıtları tutan servis üretir. Başkanlığın belirleyeceği biçim henüz yoktur. | [döküm biçimi](../spec/export.md) | kısmen |
| Denetçinin kayıtları incelemesi | N md. 8(1) | "Denetlenen tarafa ait her türlü basılı ve elektronik belgeyi, bilgi sistemlerinde işlenen veya saklanan verileri ve kayıt (log) dosyalarını, bilgi ve iletişim ağlarını ve bunlara ait topoloji ve yapılandırma bilgilerini," | Kayıtların ve dökümün biçimi açık ve belgelidir; denetçi kaydı okumak için özel bir yazılıma ihtiyaç duymaz, imzaları depodaki doğrulayıcıyla ya da kendi yazacağı bir doğrulayıcıyla denetleyebilir. Dökümü üreten bölüm bu depoda yoktur. | [protokol](../spec/protocol.md), [doğrulayıcı](../spec/verify/README.md) | kısmen |
<!-- eslestirme:bitir -->

## 4. SpaceGoat'ın yapmadıkları

Aşağıdakiler taslaklarda yer alır ve SpaceGoat'ın kapsamı dışındadır.

- **Envanterin eksiksiz olduğunu göstermek.** Hub yalnız dinlediği ağ bölümünde konuşan cihazı görür. Kapalı, sessiz ya da başka bölümdeki cihazı göremez. Envanterin D md. 30(2)'deki alanlarının çoğunu (sahip, sorumlu, kritik hizmet, veri sınıfı, sürüm, seri numarası, lisans) üretmez.
- **Kuruluşun loglarını tutmak.** D md. 42(1) ve 42(2) kullanıcı ve sistem işlemlerinin kaydını ister. Hub bu kayıtları üretmez; yalnız kendi gözlem kayıtlarını imzalar.
- **Tehdit tespiti, engelleme, izolasyon.** D md. 62 otomatik müdahale ve izolasyon kabiliyeti ister. SpaceGoat yalnız gözler; hiçbir cihazı engellemez, ağdan düşürmez, trafiğe karışmaz. Bu bir tasarım kuralıdır ve değişmeyecektir.
- **Aktif tarama, zafiyet taraması, sızma testi** (D md. 34, 63).
- **Ağ ayrımının yapıldığını göstermek.** Bir bölümde beklenmeyen bir cihazın görülmesi kayda geçer; hiçbir şeyin görülmemesi ayrımın yapıldığını göstermez.
- **Kablosuz ağ denetimi** (D md. 59/9, 59/10). Hub kablosuz yayını dinlemez.
- **Olay bildirimi ve UVET bildirimi** (D md. 7, 27, 33). Bunları kuruluş yapar.
- **Kayıt saklama süreleri** (D md. 42/3 iki yıl; D md. 31/3, 50/5 ve benzerleri beş yıl). Saklama servisin ve kuruluşun işidir.
- **SOME kurmak, BGYS belgesi, bağımsız denetim.** N md. 25(4) uyarınca öz değerlendirme sonuçları bağımsız ve tarafsız güvence sayılmaz; SpaceGoat kayıtları da bu niteliği değiştirmez.
- **Gözlemin doğruluğu.** İmza, kaydın sonradan değişmediğini gösterir. Gözlemin doğru ya da eksiksiz olduğunu göstermez.

Taslaklarda "yetkisiz cihaz tespiti" diye açık bir yükümlülük yoktur.

## 5. Hub'ı ağınıza koyarken

Hub'ın kendisi de bir varlıktır ve taslakların cihazlara ilişkin hükümleri ona da uygulanır.

- **Envanter:** Hub'ı kendi envanterinize ve yazılım envanterinize kaydedin (D md. 30/1, 30/7).
- **Çıkış kuralı:** Hub yalnız bir adrese HTTPS ile bağlanır. Güvenlik duvarında yalnız o adrese izin veren dar bir kural yeterlidir (D md. 38/2).
- **Varsayılan parola:** Hub'da parola ile girilen bir yönetim arayüzü yoktur; kimliği kurulumda üretilen anahtardır (D md. 36/2).
- **Zaman:** Hub'ın çalıştığı sistemin saatini kuruluşunuzun ortak zaman kaynağına bağlayın (D md. 44/1).
- **Operasyonel teknoloji ağları:** D md. 60(1) bu ağların bütün dış ağlardan ayrılmasını ister. Dışarıya bağlanan bir Hub'ı böyle bir ağa koymayın.
- **Kritik altyapı:** D md. 58 verinin Türkiye'de ve Başkanlıkça yetkilendirilen bir hizmet sağlayıcıda barınmasını, D md. 56(8) siber güvenlik ürünlerinin yetkilendirilmiş üreticilerden temin edilmesini ister. Bu yetkilendirmelerin usulü taslaklarda yer almaz. SpaceGoat ya da onu işleten bir servis için böyle bir yetkilendirme yoktur.

## 6. Yorumlar

Yorum: D md. 61(1), veri toplayan uç cihazların diğer ağ bölümlerinden ayrılmasını ister. Pasif bir dinleyici ise gözlediği ağ bölümünün içinde olmak zorundadır. Bu iki ihtiyacın nasıl bağdaşacağı kuruluşun ağ tasarımına bağlıdır; her ağ bölümüne ayrı bir Hub gerekebilir.

Yorum: D md. 42(3) "kriptografik yöntemler veya zaman damgası" der, hangi yöntemin yeterli olduğunu söylemez. Olay başına imza ve kesintisiz sıra numarasının bu ifadenin içinde sayılıp sayılmayacağı nihai metne ve uygulama esaslarına bağlıdır.

Yorum: D md. 7(4) Başkanlığa UVET'teki bilgilerin doğruluğu için "elektronik doğrulama yöntemlerini" kullanma imkânı verir. Kuruluşun kendi envanterini gözlemle karşılaştırması taslakta bir yükümlülük değildir; yine de D md. 30(8)'deki gözden geçirmeyi kolaylaştırır.

Yorum: Taslaklar yürürlüğe girdiğinde bu belge nihai metne göre yeniden yazılacaktır. O zamana kadar buradaki madde numaralarına dayanarak karar vermeyin.
