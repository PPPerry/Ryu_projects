import random
TOLERANCE = 1e-6  # everything below is considered zero

def improveLabels(val):
    #to confirm a GoodSet
    for u in S:
        lu[u] -= val
    for v in V:
        if v in T:
            lv[v] += val
        else:
            minSlack[v][0] -= val

def improveMatching(v):
    #to find a GoodPath
    u = T[v]
    if u in Mu:
        improveMatching(Mu[u])
    Mu[u] = v
    Mv[v] = u

def slack(u,v): return lu[u]+lv[v]-w[u][v]
    #Reduced Cost

def augment():
    #to improve the GoodPath
    while True:
        # select edge (u,v) with u in S, v not in T and min slack
        ((val, u), v) = min([(minSlack[v], v) for v in V if v not in T])
        assert u in S
        assert val > - TOLERANCE
        if val > TOLERANCE:
            improveLabels(val)
        # now we are sure that (u,v) is saturated
        assert abs(slack(u,v)) < TOLERANCE  # test zero slack with tolerance
        T[v] = u                            # add (u,v) to the tree
        if v in Mv:
            u1 = Mv[v]                      # matched edge,
            assert not u1 in S
            S[u1] = True                    # ... add endpoint to tree
            for v in V:                     # maintain minSlack
                if not v in T and minSlack[v][0] > slack(u1,v):
                    minSlack[v] = [slack(u1,v), u1]
        else:
            improveMatching(v)              # v is a free vertex
            return

def maxWeightMatching(weights):
    #input the weight Matrix
    global U,V,S,T,Mu,Mv,lu,lv, minSlack, w
    w  = weights
    n  = len(w)
    U  = V = range(n)
    lu = [ max([w[u][v] for v in V]) for u in U]  # start with trivial labels
    lv = [ 0                         for v in V]
    Mu = {}                                       # start with empty matching
    Mv = {}
    while len(Mu)<n:
        free = [u for u in V if u not in Mu]      # choose free vertex u0
        u0 = free[0]
        S = {u0: True}                            # grow tree from u0 on
        T = {}
        minSlack = [[slack(u0,v), u0] for v in V]
        augment()
    val = sum(lu)+sum(lv)
    return (Mu, Mv, val)

if __name__=='__main__':
    #define the num
    switches_num = 13
    measure_num = 20
    flow_num = 1000

    #define randomly the weight matrix 
    weight_matrix = [[0 for v in range(flow_num)] for u in range(flow_num)]

    for i in range(switches_num):
        for j in range(flow_num):
            w = random.randint(0,10)
            for k in range(measure_num):
                weight_matrix[j][k + i * measure_num] = w

    match = maxWeightMatching(weight_matrix)
    flows = match[0]
    for key in flows:
        if weight_matrix[key][flows[key]] != 0:
            print(key, ': ', flows[key], end = '')

    print('')
    print("the final cost is: ", match[2])

