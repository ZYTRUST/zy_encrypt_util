//
//  ViewController.swift
//  zy_encrypt_util
//
//  Created by ZYTRUST SA on 07/21/2022.
//  Copyright (c) 2022 ZYTRUST SA. All rights reserved.
//

import UIKit
import zy_encrypt_util

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
        ZyEncrypt.encriptar(inputdata: "", pass:"")
    }

}

