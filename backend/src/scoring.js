// Strict word-by-word scorer. Punctuation/case/matra differences remain errors.
// A dynamic-programming alignment identifies substitutions, omissions and insertions.
export function scoreTranscription(reference, submitted, elapsedMinutes = 1) {
  const a = (reference || '').trim().split(/\s+/).filter(Boolean);
  const b = (submitted || '').trim().split(/\s+/).filter(Boolean);
  const dp = Array.from({length:a.length+1},()=>Array(b.length+1).fill(0));
  for(let i=0;i<=a.length;i++) dp[i][0]=i;
  for(let j=0;j<=b.length;j++) dp[0][j]=j;
  for(let i=1;i<=a.length;i++) for(let j=1;j<=b.length;j++)
    dp[i][j]=Math.min(dp[i-1][j]+1,dp[i][j-1]+1,dp[i-1][j-1]+(a[i-1]===b[j-1]?0:1));
  const mistakes=[]; let i=a.length,j=b.length;
  while(i>0||j>0){
    if(i>0&&j>0&&dp[i][j]===dp[i-1][j-1]+(a[i-1]===b[j-1]?0:1)){
      if(a[i-1]!==b[j-1]) mistakes.push({type:'wrong',expected:a[i-1],actual:b[j-1]});
      i--;j--;
    } else if(i>0&&dp[i][j]===dp[i-1][j]+1){mistakes.push({type:'omitted',expected:a[i-1],actual:null});i--;}
    else {mistakes.push({type:'extra',expected:null,actual:b[j-1]});j--;}
  }
  mistakes.reverse();
  const errors=dp[a.length][b.length];
  const accuracy=a.length?Math.max(0,((a.length-errors)/a.length)*100):0;
  const wpm=elapsedMinutes>0?b.length/elapsedMinutes:0;
  return {accuracy:Number(accuracy.toFixed(2)),wpm:Number(wpm.toFixed(2)),errors,referenceWords:a.length,typedWords:b.length,mistakes};
       }
