import React, { useState } from 'react';
import { User, UserRank } from '../types';
import { 
  Medal, 
  ShieldCheck, 
  Star, 
  CheckCircle2, 
  Trophy, 
  X, 
  ArrowUpCircle, 
  ChevronLeft, 
  Copy, 
  Camera, 
  UploadCloud,
  FileText,
  CircleHelp,
  Info,
  ChevronRight,
  AlertCircle
} from 'lucide-react';
import { compressImage } from '../utils';

interface RankLimitsProps {
  user: User | null;
  isGlobalProcessing: boolean;
  onBack: () => void;
  onUpgrade: (targetRank: UserRank, bill: string) => Promise<void> | void;
}

enum RankView {
  LIST = 'LIST',
  PAYMENT = 'PAYMENT'
}

const RankLimits: React.FC<RankLimitsProps> = ({ user, isGlobalProcessing, onBack, onUpgrade }) => {
  const [view, setView] = useState<RankView>(RankView.LIST);
  const [selectedRank, setSelectedRank] = useState<any>(null);
  const [billImage, setBillImage] = useState<string | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [showHelp, setShowHelp] = useState(false);
  const [copyToast, setCopyToast] = useState(false);

  const ranks = [
    {
      id: 'standard',
      name: 'TIÊU CHUẨN',
      code: 'TIEUCHUAN',
      min: '1.000.000 đ',
      max: '2.000.000 đ',
      limitVal: 2000000,
      icon: <Medal size={24} className="text-gray-500" />,
      features: ['Hạn mức 1 - 2 triệu', 'Duyệt trong 24h'],
    },
    {
      id: 'bronze',
      name: 'ĐỒNG',
      code: 'DONG',
      min: '1.000.000 đ',
      max: '3.000.000 đ',
      limitVal: 3000000,
      icon: <Star size={24} className="text-orange-300" />,
      features: ['Hạn mức 1 - 3 triệu', 'Ưu tiên duyệt lệnh'],
    },
    {
      id: 'silver',
      name: 'BẠC',
      code: 'BAC',
      min: '1.000.000 đ',
      max: '4.000.000 đ',
      limitVal: 4000000,
      icon: <Star size={24} className="text-blue-200" />,
      features: ['Hạn mức 1 - 4 triệu', 'Hỗ trợ 24/7'],
    },
    {
      id: 'gold',
      name: 'VÀNG',
      code: 'VANG',
      min: '1.000.000 đ',
      max: '5.000.000 đ',
      limitVal: 5000000,
      icon: <Medal size={24} className="text-yellow-400" />,
      features: ['Hạn mức 1 - 5 triệu', 'Giảm 10% phí phạt'],
    },
    {
      id: 'diamond',
      name: 'KIM CƯƠNG',
      code: 'KIMCUONG',
      min: '1.000.000 đ',
      max: '10.000.000 đ',
      limitVal: 10000000,
      icon: <ShieldCheck size={24} className="text-blue-400" />,
      features: ['Hạn mức 1 - 10 triệu', 'Duyệt lệnh tức thì'],
    }
  ];

  const currentRankIndex = ranks.findIndex(r => r.id === (user?.rank || 'standard'));

  const handleOpenPayment = (rank: any) => {
    setSelectedRank(rank);
    setView(RankView.LIST); // Need this for animation
    setTimeout(() => setView(RankView.PAYMENT), 50);
    setBillImage(null);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopyToast(true);
    setTimeout(() => setCopyToast(false), 2000);
  };

  const handleBillUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setIsUploading(true);
      const reader = new FileReader();
      reader.onloadend = async () => {
        const compressed = await compressImage(reader.result as string, 800, 800);
        setBillImage(compressed);
        setIsUploading(false);
      };
      reader.readAsDataURL(file);
    }
  };

  const handleConfirmUpgrade = async () => {
    if (billImage && selectedRank && !isSubmitting && !isGlobalProcessing) {
      setIsSubmitting(true);
      try {
        await onUpgrade(selectedRank.id as UserRank, billImage);
        setView(RankView.LIST);
      } catch (e) {
        console.error("Lỗi nâng hạng:", e);
      } finally {
        setIsSubmitting(false);
      }
    } else if (!billImage) {
      alert("Vui lòng tải lên ảnh Bill thanh toán phí nâng hạng.");
    }
  };

  const hasPending = !!user?.pendingUpgradeRank;

  if (view === RankView.PAYMENT && selectedRank) {
    const fee = selectedRank.limitVal * 0.05;
    const transferContent = `${selectedRank.code} ${user?.id || 'xxxx'}`;

    return (
      <div className="w-full h-full bg-black animate-in slide-in-from-right duration-300 flex flex-col p-5 overflow-y-auto pb-24 relative">
        {copyToast && (
          <div className="fixed top-8 left-1/2 -translate-x-1/2 z-[1000] animate-in fade-in slide-in-from-top-4 duration-300">
            <div className="bg-green-600 text-white px-5 py-2.5 rounded-full font-black text-[9px] uppercase tracking-widest shadow-2xl flex items-center gap-2">
              <CheckCircle2 size={14} />
              Đã sao chép thành công
            </div>
          </div>
        )}

        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <button 
              onClick={() => setView(RankView.LIST)}
              className="w-9 h-9 bg-white/5 rounded-full flex items-center justify-center text-white"
            >
              <ChevronLeft size={18} />
            </button>
            <h2 className="text-lg font-black text-white uppercase tracking-tighter">Phí nâng hạng {selectedRank.name}</h2>
          </div>
          <button 
            onClick={() => setShowHelp(!showHelp)}
            className={`w-9 h-9 rounded-full flex items-center justify-center transition-all ${showHelp ? 'bg-[#ff8c00] text-black shadow-lg shadow-orange-500/20' : 'bg-white/5 text-gray-400'}`}
          >
            <CircleHelp size={20} />
          </button>
        </div>

        {showHelp && (
          <div className="bg-[#ff8c00]/5 border border-[#ff8c00]/20 rounded-2xl p-5 mb-6 animate-in fade-in zoom-in duration-300 space-y-3">
             <div className="flex items-center gap-2">
                <Info size={16} className="text-[#ff8c00]" />
                <span className="text-[10px] font-black text-[#ff8c00] uppercase tracking-widest">Hướng dẫn chi tiết nâng hạng</span>
             </div>
             <div className="space-y-2.5">
                <div className="flex gap-2.5">
                  <div className="w-4 h-4 bg-[#ff8c00] rounded-full flex items-center justify-center shrink-0 font-black text-[9px] text-black">1</div>
                  <p className="text-[9px] font-bold text-gray-300 leading-tight">
                    Nhấn biểu tượng sao chép để lấy <span className="text-[#ff8c00]">STK</span>, <span className="text-[#ff8c00]">Số tiền</span> và <span className="text-[#ff8c00]">Nội dung chuyển khoản</span>.
                  </p>
                </div>
                <div className="flex gap-2.5">
                  <div className="w-4 h-4 bg-[#ff8c00] rounded-full flex items-center justify-center shrink-0 font-black text-[9px] text-black">2</div>
                  <p className="text-[9px] font-bold text-gray-300 leading-tight">
                    Mở ứng dụng Ngân hàng của bạn, thực hiện chuyển tiền chính xác thông tin đã lấy ở Bước 1.
                  </p>
                </div>
                <div className="flex gap-2.5">
                  <div className="w-4 h-4 bg-[#ff8c00] rounded-full flex items-center justify-center shrink-0 font-black text-[9px] text-black">3</div>
                  <p className="text-[9px] font-bold text-gray-300 leading-tight">
                    Chụp lại màn hình <span className="text-white">Biên lai giao dịch (Bill)</span> thành công.
                  </p>
                </div>
                <div className="flex gap-2.5">
                  <div className="w-4 h-4 bg-[#ff8c00] rounded-full flex items-center justify-center shrink-0 font-black text-[9px] text-black">4</div>
                  <p className="text-[9px] font-bold text-gray-300 leading-tight">
                    Tải ảnh Bill lên mục <span className="text-white">Tải ảnh Bill xác nhận</span> bên dưới và nhấn Gửi yêu cầu.
                  </p>
                </div>
             </div>
          </div>
        )}

        <div className="w-full min-h-[180px] bg-gradient-to-br from-[#1c1c1e] to-[#0a0a0a] rounded-3xl p-6 relative overflow-hidden shadow-2xl border border-white/10 mb-6 flex flex-col justify-between">
          <div className="flex justify-between items-start mb-3">
            <div className="flex items-center gap-2.5">
              <div className="w-9 h-9 bg-[#ff8c00] rounded-xl flex items-center justify-center font-black text-black text-[11px]">NDV</div>
              <span className="text-[9px] font-black text-white uppercase tracking-wider">VIP PLATINUM</span>
            </div>
            <div className="p-1 bg-orange-500/10 rounded-full">
              <ShieldCheck size={20} className="text-[#ff8c00]" />
            </div>
          </div>
          
          <div className="space-y-0.5 mb-3">
            <span className="text-[7px] font-black text-gray-500 uppercase tracking-widest">SỐ TÀI KHOẢN</span>
            <div className="flex items-center justify-between">
              <p className="text-xl font-mono font-black text-white tracking-[0.1em]">TIMOQNCGLIWQCLQ</p>
              <button onClick={() => copyToClipboard('TIMOQNCGLIWQCLQ')} className="p-1.5 bg-white/5 rounded-lg text-[#ff8c00] active:scale-90 transition-all"><Copy size={14} /></button>
            </div>
          </div>
          
          <div className="flex justify-between items-end mt-1">
            <div className="space-y-0.5">
              <p className="text-[7px] font-black text-gray-500 uppercase tracking-widest">CHỦ TÀI KHOẢN</p>
              <p className="text-[11px] font-black text-white uppercase tracking-tight">DO TRUNG NGON</p>
            </div>
            <div className="text-right">
              <p className="text-[7px] font-black text-gray-500 uppercase tracking-widest mb-0.5">NGÂN HÀNG</p>
              <p className="text-[10px] font-black text-[#ff8c00] uppercase tracking-tighter">TIMO (BẢN VIỆT)</p>
            </div>
          </div>
        </div>

        {/* Optimized 2-column detail section */}
        <div className="bg-[#111111] border border-white/5 rounded-2xl p-5 grid grid-cols-2 gap-3 mb-6 shadow-inner">
           <div className="flex flex-col gap-1.5 border-r border-white/5 pr-3">
              <div className="flex justify-between items-center">
                 <span className="text-[8px] font-black text-gray-500 uppercase tracking-widest">Nội dung</span>
                 <button onClick={() => copyToClipboard(transferContent)} className="p-1 bg-white/5 rounded text-gray-400 hover:text-white transition-all"><Copy size={10} /></button>
              </div>
              <p className="text-lg font-black text-[#ff8c00] tracking-widest break-all">{transferContent}</p>
           </div>
           
           <div className="flex flex-col gap-1.5 pl-3">
              <div className="flex justify-between items-center">
                 <span className="text-[8px] font-black text-gray-500 uppercase tracking-widest">Số tiền</span>
                 <button onClick={() => copyToClipboard(fee.toString())} className="p-1 bg-white/5 rounded text-gray-400 hover:text-white transition-all"><Copy size={10} /></button>
              </div>
              <p className="text-lg font-black text-[#ff8c00] tracking-tight">{fee.toLocaleString()} đ</p>
           </div>
        </div>

        <div className="bg-[#111111] border border-white/5 rounded-3xl p-6 space-y-5">
           <div className="flex items-center gap-2 text-gray-400">
              <Camera size={16} />
              <h3 className="text-[9px] font-black uppercase tracking-widest">Tải ảnh Bill xác nhận</h3>
           </div>
           <div 
             onClick={() => document.getElementById('billInputRankUpgrade')?.click()}
             className={`aspect-video w-full rounded-2xl border-2 border-dashed flex flex-col items-center justify-center gap-3 cursor-pointer relative overflow-hidden transition-all ${billImage ? 'border-green-500 bg-green-500/5' : 'border-gray-800 bg-black hover:border-[#ff8c00]/30'}`}
           >
              <input id="billInputRankUpgrade" type="file" accept="image/*" hidden onChange={handleBillUpload} />
              {billImage ? (
                <>
                  <img src={billImage} className="w-full h-full object-cover opacity-60" />
                  <div className="absolute inset-0 flex flex-col items-center justify-center bg-black/40">
                    <CheckCircle2 size={28} className="text-green-500 mb-1.5" />
                    <span className="text-[9px] font-black text-white">BILL ĐÃ TẢI LÊN</span>
                  </div>
                </>
              ) : (
                <>
                  {isUploading ? <div className="animate-spin border-3 border-[#ff8c00] border-t-transparent w-6 h-6 rounded-full" /> : <UploadCloud size={28} className="text-gray-700" />}
                  <p className="text-[9px] font-black text-gray-500 uppercase tracking-widest">Chọn ảnh Biên lai giao dịch</p>
                </>
              )}
           </div>
        </div>

        <button
          onClick={handleConfirmUpgrade}
          disabled={!billImage || isSubmitting || isGlobalProcessing}
          className={`w-full py-4 rounded-3xl font-black text-xs tracking-[0.2em] transition-all mt-6 shadow-2xl ${billImage && !isSubmitting && !isGlobalProcessing ? 'bg-[#ff8c00] text-black shadow-orange-950/40 active:scale-95' : 'bg-white/5 text-gray-600 cursor-not-allowed opacity-50'}`}
        >
          {isSubmitting || isGlobalProcessing ? 'ĐANG XỬ LÝ...' : (billImage ? 'GỬI YÊU CẦU NÂNG CẤP' : 'VUI LÒNG ĐÍNH KÈM BILL')}
        </button>
      </div>
    );
  }

  return (
    <div className="w-full bg-black px-5 pb-24 space-y-3 animate-in fade-in duration-500">
      <div className="flex items-center justify-between px-1 pt-5">
        <div className="flex items-center gap-3">
          <button 
            onClick={onBack}
            className="w-8 h-8 bg-[#111111] border border-white/5 rounded-full flex items-center justify-center text-white active:scale-90 transition-all"
          >
            <X size={16} />
          </button>
          <h2 className="text-lg font-black text-white tracking-tighter uppercase">Hạng & Hạn mức</h2>
        </div>
        <button 
          onClick={() => setShowHelp(!showHelp)}
          className={`w-8 h-8 rounded-full flex items-center justify-center transition-all ${showHelp ? 'bg-[#ff8c00] text-black shadow-lg shadow-orange-500/20' : 'bg-white/5 text-gray-500'}`}
        >
          <CircleHelp size={18} />
        </button>
      </div>

      {showHelp && (
        <div className="bg-[#ff8c00]/5 border border-[#ff8c00]/20 rounded-2xl p-5 animate-in fade-in zoom-in duration-300 space-y-3">
           <div className="flex items-center gap-2">
              <Info size={14} className="text-[#ff8c00]" />
              <span className="text-[9px] font-black text-[#ff8c00] uppercase tracking-widest">Quy định nâng hạng</span>
           </div>
           <div className="space-y-2.5">
              <div className="flex gap-2.5">
                <div className="w-4 h-4 bg-[#ff8c00] rounded-full flex items-center justify-center shrink-0 font-black text-[9px] text-black">1</div>
                <p className="text-[9px] font-bold text-gray-300 leading-tight">
                  <span className="text-[#ff8c00]">Lợi ích:</span> Tăng hạn mức vay tối đa, ưu tiên xét duyệt lệnh giải ngân và nhận được các ưu đãi về phí phạt.
                </p>
              </div>
              <div className="flex gap-2.5">
                <div className="w-4 h-4 bg-[#ff8c00] rounded-full flex items-center justify-center shrink-0 font-black text-[9px] text-black">2</div>
                <p className="text-[9px] font-bold text-gray-300 leading-tight">
                  <span className="text-[#ff8c00]">Phí nâng hạng:</span> Tương đương 5% giá trị hạn mức tối đa của hạng thành viên mới.
                </p>
              </div>
              <div className="flex gap-2.5">
                <div className="w-4 h-4 bg-[#ff8c00] rounded-full flex items-center justify-center shrink-0 font-black text-[9px] text-black">3</div>
                <p className="text-[9px] font-bold text-gray-300 leading-tight">
                  <span className="text-[#ff8c00]">Thời gian:</span> Yêu cầu nâng hạng sẽ được hệ thống xét duyệt trong vòng 30 phút đến 2 giờ làm việc.
                </p>
              </div>
           </div>
        </div>
      )}

      <div className="space-y-2.5">
        {ranks.map((rank, idx) => {
          const isCurrent = user?.rank === rank.id;
          const isTargetPending = user?.pendingUpgradeRank === rank.id;
          const isHigherRank = idx > currentRankIndex;

          return (
            <div 
              key={rank.id}
              className={`bg-[#111111] rounded-2xl p-5 relative transition-all duration-300 border ${
                isCurrent ? 'border-[#ff8c00] shadow-[0_0_20px_rgba(255,140,0,0.1)]' : 'border-white/5'
              } ${!isCurrent && (currentRankIndex === ranks.length - 1 || hasPending) ? 'opacity-40' : 'opacity-100'}`}
            >
              {(isCurrent || isTargetPending) && (
                <div className={`absolute right-4 top-4 text-[7px] font-black px-2.5 py-1 rounded-full tracking-widest uppercase ${
                  isCurrent ? 'bg-[#ff8c00] text-black' : 'bg-blue-500 text-white'
                }`}>
                  {isCurrent ? 'Hiện tại' : 'Đang duyệt'}
                </div>
              )}

              <div className="flex gap-3.5 mb-3.5">
                <div className="w-12 h-12 bg-white/5 rounded-xl flex items-center justify-center">
                  {React.cloneElement(rank.icon as React.ReactElement, { size: 20 })}
                </div>
                <div className="flex flex-col justify-center">
                  <h3 className="text-lg font-black text-white leading-tight tracking-tight">{rank.name}</h3>
                  <p className="text-[8px] font-black text-gray-500 uppercase tracking-widest">Hạn mức: {rank.min} - {rank.max}</p>
                </div>
              </div>

              <div className="space-y-1.5">
                {rank.features.map((feature, fIdx) => (
                  <div key={fIdx} className="flex items-center gap-1.5">
                    <div className={`w-3 h-3 rounded-full border flex items-center justify-center ${isCurrent ? 'border-[#ff8c00]' : 'border-gray-800'}`}>
                      <CheckCircle2 size={7} className={isCurrent ? 'text-[#ff8c00]' : 'text-gray-800'} />
                    </div>
                    <span className={`text-[10px] font-bold ${isCurrent ? 'text-gray-200' : 'text-gray-500'}`}>{feature}</span>
                  </div>
                ))}
              </div>

              {isHigherRank && !hasPending && (
                <div className="mt-3.5 pt-3.5 border-t border-white/5">
                  <button 
                    onClick={() => handleOpenPayment(rank)}
                    className="w-full bg-[#ff8c00] text-black font-black py-3 rounded-xl flex items-center justify-center gap-2 shadow-xl shadow-orange-950/20 active:scale-95 transition-all text-[9px] uppercase tracking-[0.1em]"
                  >
                    <ArrowUpCircle size={14} />
                    NÂNG CẤP NGAY
                  </button>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default RankLimits;