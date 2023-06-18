#include<bits/stdc++.h>
using namespace std;


int solve(vector<int> &ans){
    long long res = (1 << 30)-1;
    for(int i = 0;i<ans.size();i++){
        for(int j = 31;j>=0;j--){
            int bit = (ans[i] >> j) & 1;

            if(bit){
                cout<<ans[i]<<" "<<j<<" "<<((1 << (j+1)) - 1)<<endl;
                res &= ((1 << (j+1)) - 1);
                break;
            }
        }
    }
    return res;
}
int main() {
    vector<int> ans = {1,3,5,8};
    cout<<solve(ans)<<endl;
}