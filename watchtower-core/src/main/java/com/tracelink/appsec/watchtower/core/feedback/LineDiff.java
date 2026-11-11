package com.tracelink.appsec.watchtower.core.feedback;

import java.util.ArrayList;
import java.util.List;

/**
 * Deterministic line diff for one small file at two commits. The common prefix and suffix are
 * trimmed, then a longest-common-subsequence walk finds changed ranges. A middle too large for the
 * table is reported as one changed range rather than guessed.
 */
final class LineDiff {
 /** 1-based inclusive line ranges; an empty side has {@code to < from}. */
 record Change(int oldFrom,int oldTo,int newFrom,int newTo) {
  boolean coversOld(int line){return line>=oldFrom&&line<=oldTo;}
 }
 static final long MAX_TABLE_CELLS=2_000_000;
 private LineDiff() { }
 static List<Change> changes(List<String> before,List<String> after){
  int prefix=0;while(prefix<before.size()&&prefix<after.size()&&before.get(prefix).equals(after.get(prefix)))prefix++;
  int suffix=0;while(suffix<before.size()-prefix&&suffix<after.size()-prefix&&before.get(before.size()-1-suffix).equals(after.get(after.size()-1-suffix)))suffix++;
  var a=before.subList(prefix,before.size()-suffix);var b=after.subList(prefix,after.size()-suffix);
  if(a.isEmpty()&&b.isEmpty())return List.of();
  if((long)(a.size()+1)*(b.size()+1)>MAX_TABLE_CELLS)return List.of(new Change(prefix+1,prefix+a.size(),prefix+1,prefix+b.size()));
  int n=a.size(),m=b.size();int[][] lcs=new int[n+1][m+1];
  for(int i=n-1;i>=0;i--)for(int j=m-1;j>=0;j--)lcs[i][j]=a.get(i).equals(b.get(j))?lcs[i+1][j+1]+1:Math.max(lcs[i+1][j],lcs[i][j+1]);
  List<Change> changes=new ArrayList<>();int i=0,j=0,startI=-1,startJ=-1;
  while(i<n||j<m){
   if(i<n&&j<m&&a.get(i).equals(b.get(j))){
    if(startI>=0){changes.add(new Change(prefix+startI+1,prefix+i,prefix+startJ+1,prefix+j));startI=-1;}
    i++;j++;continue;
   }
   if(startI<0){startI=i;startJ=j;}
   if(j>=m||i<n&&lcs[i+1][j]>=lcs[i][j+1])i++;else j++;
  }
  if(startI>=0)changes.add(new Change(prefix+startI+1,prefix+i,prefix+startJ+1,prefix+j));
  return changes;
 }
}
