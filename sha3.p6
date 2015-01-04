use v6;

class Digest::SHA3 {
	has $.b = 1600;

	method !w {
		floor($.b/25);
	}

	method !l {
		log(floor($.b/25), 2);
	}

	method !theta(@A) {
		my $w = self!w;
		my @C;
		my @D;
		my @A2 = @A.values;
		for ^5 -> $x {
			for ^$w -> $z {
				@C[$x][$z] = [+^] @A[$x][^5][$z];
			}
		}
		for ^5 -> $x {
			for ^$w -> $z {
				@D[$x][$z] = @C[($x-1) % 5][$z] +^ @C[($x+1)%5][($z-1) % $w];
			}
		}
		for ^5 -> $x {
			for ^5 -> $y {
				for ^$w -> $z {
					@A2[$x][$y][$z] = @A[$x][$y][$z] +^ @D[$x][$z];
				}
			}
		}
		@A2;
	}
	
	method !rho(@A) {
		my $w = self!w;
		my @A2 = @A.values;
		my $x = 1;
		my $y = 0;
		for 0..23 -> $t {
			for ^$w -> $z {
				@A2[$x][$y][$z] = @A[$x][$y][($z-((($t+1)*($t+2))/2)) % $w];
			}
			my $temp = $x;
			$x = $y;
			$y = ((2 * $temp) + (3 * $y)) % 5;
		}
		@A2;
	}
	
	method !pi(@A) {
		my $w = self!w;
		my @A2 = @A.values;
		for ^5 -> $x {
			for ^5 -> $y {
				for ^$w -> $z {
					@A2[$x][$y][$z] = @A[($x + (3 * $y)) % 5][$x][$z];
				}
			}
		}
		@A2;
	}
	
	method !chi(@A) {
		my $w = self!w;
		my @A2 = @A.values;
		for ^5 -> $x {
			for ^5 -> $y {
				for ^$w -> $z {
					@A2[$x][$y][$z] = @A[$x][$y][$z] +^ ((@A[($x+1) % 5][$y][$z] +^ 1) * @A[($x+2) % 5][$y][$z]);
				}
			}
		}
		@A2;
	}
	
	method !rc($t) {
		if $t % 255 == 0 {
			1;
		} else {
			my @R = @(1,0,0,0,0,0,0,0);
			for 1..($t % 255) -> $i {
				unshift @R, 0;
				@R[0] = @R[0] + @R[8];
				@R[4] = @R[4] + @R[8];
				@R[5] = @R[5] + @R[8];
				@R[6] = @R[6] + @R[8];
				@R = @R[0..7];
			}
			@R[0];
		}
	}
	
	method !iota($i, @A) {
		my $w = self!w;
		my @A2 = @A.values;
		my @RC = 0 xx $w;
		for 0..(self!l) -> $j {
			@RC[(2**$j) - 1] = self!rc($j + (7 * $i));
		}
		for ^$w -> $z {
			@A2[0][0][$z] = @A2[0][0][$z] +^ @RC[$z];
		}
		@A2;
	}
	
	method !toStateArray(Blob $S) {
		my $w = self!w();
		my @A;
		for ^5 -> $x {
			for ^5 -> $y {
				for ^$w -> $z {
					@A[$x][$y][$z] = $S[$w * ((5 * $y) + $x) + $z];
				}
			}
		}
		@A;
	}
	
	method !toString(@A) {
		my buf8 $S = buf8.new;
		my $w = self!w;
		for ^5 -> $y {
			for ^5 -> $x {
				for ^$w -> $z {
					$S[$S.elems] = @A[$x][$y][$z];
				}
			}
		}
		$S;
	}
	
	method !keccak-p($S, $b, $n) {
		my @A = self!toStateArray($S);
		for (2*self!l + 12 - $n)..(2 * self!l + 12 - 1) -> $i {
			@A = self!iota(self!chi(self!pi(self!rho(self!theta(@A)))), $i);
		}
		self!toString(@A);
	}
	
	method !pad($x, $m) {
		my $j = (($m * -1) - 2) % $x;
		buf8.new(1, 0 xx $j, 1)
	}
	
	method !sponge($M, $d, $r) {
		my $P = $M ~ self!pad($r, $M.elems);
		my $n = $P.elems/$r;
		my $c = $.b - $r;
		my @Pn = gather { take $P[$_*$r..$_*$r+$r-1] for ^($P.elems/$r); }
		my $S = buf8.new(0 xx $.b);
		for ^($n-1) -> $i {
			$S = self!keccak-p($S ~^ ($P[$i] ~ (0 xx $c)), $.b, $n);
		}
		my buf8 $Z = buf8.new;
		until $d <= $Z.elems {
			$Z ~= $S.subbuf(0,$r);
			return $Z.subbuf(0,$d) if $d <= $Z.elems;
			$S = self!keccak-p($S, $.b, $n);
		}
	}
	
	method !keccak($c, $M, $d) {
		self!sponge($M, $d, 1600-$c);
	}

	method !toHex(Blob $b) {
		gather {
			take .base(16) for gather { 
				take [+] (.value * 2 ** (3 - .key) for $b[$_*4..$_*4+3].pairs) for ^($b.elems/4); 
			} 
		}.Str.subst(' ', '', :g).lc;
	}

	method SHA3_224(Blob $M, $d=56) {
		self!toHex(self!keccak(448, $M ~ buf8.new(0,1), 224).subbuf(0, $d));
	}
	
	method SHA3_256($M) {
	
	}
	
	method SHA3_384($M) {
	
	}
	
	method SHA3_512($M) {
	
	}
	
	method SHAKE128($M) {
	
	}
	
	method SHAKE256($M) {
	
	}
}

my $sha = Digest::SHA3.new;
my $str = "This is the beginning.";
my $buf = buf8.new(0,1,0,1,0,1,0,0,0,1,1,0,1,0,0,0,0,1,1,0,1,0,0,1,0,1,1,1,0,0,1,1,0,0,1,0,1,1,1,0);
say $sha.SHA3_224($buf);
# vim: ft=perl6
