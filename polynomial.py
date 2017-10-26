def xpow(n):
    return [0]*n + [1]

def degree(poly):
    """returns the degree of polynomial given in array form poly"""    
    coeff = poly[len(poly) - 1]
    while coeff == 0 and len(poly) > 1:
        poly.pop()
        coeff = poly[len(poly) - 1]         
    else:
        return [len(poly) - 1,coeff] 

def poly_add(poly1, poly2, modulus):
    """adds poly1 and poly2"""

    poly1 = poly1 + [0]*len(poly2)
    poly2 = poly2 + [0]*len(poly1)

    return [(poly1[i] + poly2[i]) % modulus for i in range(len(poly1))]

def poly_mult(poly1, poly2, modulus): 
    """takes two polynomials, poly1 and poly2, entered as arrays, and computes their multiplication"""
    mult = [0]*(len(poly1) + len(poly2) - 1)
    for i in range(len(poly1)):
        for j in range(len(poly2)):
            mult[i + j] += (poly1[i]*poly2[j] % modulus)
            mult[i + j] = mult[i + j] % modulus
    return mult

def poly_div(poly1, poly2, modulus):
    """takes two polynomials, poly1 and poly2, entered as arrays, and computes their division, poly1/poly2"""
    deg1 = degree(poly1)[0]
    deg2 = degree(poly2)[0]
    coeff2 = degree(poly2)[1]
    div = [0]*(deg1 - deg2 + 1)
    tmp = poly1
    while degree(tmp)[0] >= deg2:
        tmp_deg = degree(tmp)[0]
        tmp_coeff = degree(tmp)[1]
        tmp = [((x - (tmp_coeff/coeff2)*poly_mult(xpow(tmp_deg - deg2), poly2, modulus)[i]) % modulus) for i,x in enumerate(tmp)]
        div[tmp_deg - deg2] = tmp_coeff/coeff2
    return [div, tmp]

def poly_power(poly, n, modulus):
    new_poly = [1]
    for i in range(n):
        new_poly = poly_mult(new_poly, poly, modulus)
    return new_poly
        
    
    

        